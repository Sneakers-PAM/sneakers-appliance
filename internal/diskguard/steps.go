// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package diskguard

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

// The categories, as the audit entry and Status name them.
const (
	CategoryPodLogs = "pod-logs"
	CategoryAudit   = "os-audit"
	CategoryImages  = "images"
	CategoryUpdates = "updates"
	CategoryTmp     = "tmp"
	CategoryWAL     = "wal"
)

const (
	mib = int64(1) << 20
	gib = int64(1) << 30
)

func clamp(v, lo, hi int64) int64 { return min(max(v, lo), hi) }

// LogCap is the most the pod logs may hold on a state volume of total
// bytes: 2% of it, between 256 MiB and 2 GiB.
func LogCap(total uint64) int64 { return clamp(int64(total/50), 256*mib, 2*gib) } // #nosec G115 -- a volume size fits an int64

// LogKeepFree is the free space the pod logs leave on the state volume:
// below it, every rotated pod log goes. 15% of the volume, between 1 GiB
// and 16 GiB.
func LogKeepFree(total uint64) int64 { return clamp(int64(total*15/100), gib, 16*gib) } // #nosec G115 -- as above

// PodLogs keeps the kubelet's pod logs (/var/log, which leads to
// /var/lib/log) within LogCap and LogKeepFree, the box's equivalent of a
// journal size cap: the kubelet rotates each container's log itself
// (containerLogMaxSize and containerLogMaxFiles in the k0s config), and
// this removes the rotated files, oldest first, while the logs are over
// the cap or the volume is under the floor. A container's live log
// (<n>.log) is never touched.
type PodLogs struct {
	Dir string
	// Cap and KeepFree override LogCap and LogKeepFree when set.
	Cap, KeepFree int64
}

// Category implements Step.
func (PodLogs) Category() string { return CategoryPodLogs }

type logFile struct {
	path string
	size int64
	mod  time.Time
}

// Clean implements Step.
func (p PodLogs) Clean(_ context.Context, env Env) (Result, error) {
	var total int64
	var rotated []logFile
	err := filepath.WalkDir(p.Dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		n := allocated(fi)
		total += n
		if strings.Contains(d.Name(), ".log.") {
			rotated = append(rotated, logFile{path: path, size: n, mod: fi.ModTime()})
		}
		return nil
	})
	if err != nil {
		return Result{}, fmt.Errorf("diskguard: pod logs: %w", err)
	}
	limit, floor := LogCap(env.State.Total), LogKeepFree(env.State.Total)
	if p.Cap > 0 {
		limit = p.Cap
	}
	if p.KeepFree > 0 {
		floor = p.KeepFree
	}
	avail := int64(env.State.Avail) // #nosec G115 -- a volume size fits an int64
	sort.Slice(rotated, func(i, j int) bool { return rotated[i].mod.Before(rotated[j].mod) })
	var freed int64
	for _, f := range rotated {
		if total <= limit && (env.State.Total == 0 || avail >= floor) {
			break
		}
		n, err := env.Safety.Remove(f.path)
		if err != nil {
			return Result{Freed: freed}, err
		}
		env.Logger.Debug("diskguard: removed a rotated pod log", log.F("file", f.path), log.F("bytes", n))
		freed += n
		total -= f.size
		avail += n
	}
	return Result{Freed: freed}, nil
}

// AuditLog compresses the OS audit log's closed files and keeps its
// archive within the caps Options gives for the state volume, moving the
// oldest files to the backup volume once they've been flagged for the
// grace period (osaudit.Log.Archive). Nothing is deleted.
type AuditLog struct {
	Log     *osaudit.Log
	Options func(state Usage) osaudit.ArchiveOptions

	mu   sync.Mutex
	last *osaudit.ArchiveReport
}

// Category implements Step.
func (*AuditLog) Category() string { return CategoryAudit }

// Clean implements Step.
func (a *AuditLog) Clean(_ context.Context, env Env) (Result, error) {
	c, err := a.Log.Compress()
	if err != nil {
		return Result{Freed: c.Freed}, err
	}
	rep, err := a.Log.Archive(a.Options(env.State))
	a.mu.Lock()
	a.last = &rep
	a.mu.Unlock()
	res := Result{Freed: c.Freed + rep.Freed}
	if len(rep.Flagged) > 0 {
		res.Note = fmt.Sprintf("%d archived files flagged to move", len(rep.Flagged))
	}
	return res, err
}

// Archive is the last archive check's report, or nil before the first.
func (a *AuditLog) Archive() *osaudit.ArchiveReport {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.last
}

// ArchiveOptions are the OS audit archive's caps on the box: 5% of the
// state volume (at least 512 MiB) and 2000 files, a day's grace, then the
// backup volume's os-audit-archive directory.
func ArchiveOptions(exportDir string) func(Usage) osaudit.ArchiveOptions {
	return func(u Usage) osaudit.ArchiveOptions {
		return osaudit.ArchiveOptions{MaxBytes: max(int64(u.Total/20), 512*mib), MaxFiles: 2000, Grace: 24 * time.Hour, ExportDir: exportDir} // #nosec G115 -- a volume size fits an int64
	}
}

var digestRE = regexp.MustCompile(`sha256:[0-9a-f]{64}`)

// Images removes containerd's images that nothing on the box needs: kept
// are every image either product slot's bundle carries (the running
// release and the revert target, by the pinned digests their archives are
// named for), every digest the k0s and containerd config pin, every image
// a container uses, and every image containerd itself pins. With no slot
// image found it removes nothing.
type Images struct {
	// K0s is the installed bundle's k0s, run as ctr; Containerd its socket.
	K0s, Containerd string
	// Slots are the product slot directories (a and b), each with
	// images/<hex>.tar.
	Slots []string
	// Pinned are files whose sha256 digests are kept (k0s.yaml,
	// containerd.toml).
	Pinned []string
	// Measure reads the volume the images are on, for the bytes freed.
	Measure func() (Usage, error)
	// Run runs a command; nil runs it.
	Run func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Category implements Step.
func (Images) Category() string { return CategoryImages }

func (im Images) run(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	full := append([]string{"ctr", "--address", im.Containerd, "--namespace", "k8s.io"}, args...)
	if im.Run != nil {
		return im.Run(ctx, im.K0s, full...)
	}
	return runCommand(ctx, im.K0s, full...)
}

type image struct{ ref, digest, labels string }

func parseImages(out []byte) []image {
	var imgs []image
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || f[0] == "REF" || !digestRE.MatchString(f[2]) {
			continue
		}
		imgs = append(imgs, image{ref: f[0], digest: f[2], labels: f[len(f)-1]})
	}
	return imgs
}

// Clean implements Step.
func (im Images) Clean(ctx context.Context, env Env) (Result, error) {
	if _, err := os.Stat(im.K0s); err != nil {
		return Result{Note: "no product is installed"}, nil
	}
	keep := map[string]bool{}
	for _, s := range im.Slots {
		tars, _ := filepath.Glob(filepath.Join(s, "images", "*.tar"))
		for _, t := range tars {
			keep["sha256:"+strings.TrimSuffix(filepath.Base(t), ".tar")] = true
		}
	}
	if len(keep) == 0 {
		return Result{Note: "no release images found; nothing removed"}, nil
	}
	for _, p := range im.Pinned {
		b, err := os.ReadFile(p) // #nosec G304 -- the box's own k0s and containerd config
		if err != nil {
			continue
		}
		for _, d := range digestRE.FindAll(b, -1) {
			keep[string(d)] = true
		}
	}
	out, err := im.run(ctx, "images", "list")
	if err != nil {
		return Result{Note: "containerd doesn't answer; nothing removed"}, nil
	}
	imgs := parseImages(out)
	cs, err := im.run(ctx, "containers", "list")
	if err != nil {
		return Result{Note: "containerd's containers don't list; nothing removed"}, nil
	}
	used := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(cs))
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) >= 2 && f[0] != "CONTAINER" {
			used[f[1]] = true
		}
	}
	for _, i := range imgs {
		if used[i.ref] || strings.Contains(i.labels, "io.cri-containerd.pinned=pinned") {
			keep[i.digest] = true
		}
	}
	var drop []string
	for _, i := range imgs {
		if !keep[i.digest] {
			drop = append(drop, i.ref)
		}
	}
	if len(drop) == 0 {
		return Result{}, nil
	}
	slices.Sort(drop)
	var before Usage
	if im.Measure != nil {
		before, _ = im.Measure()
	}
	env.Logger.Info("diskguard: removing images no release needs", log.F("images", strings.Join(drop, " ")))
	if _, err := im.run(ctx, append([]string{"images", "rm", "--sync"}, drop...)...); err != nil {
		return Result{}, fmt.Errorf("diskguard: images rm: %w", err)
	}
	res := Result{Note: fmt.Sprintf("%d image references removed", len(drop))}
	if im.Measure != nil {
		if after, err := im.Measure(); err == nil && after.Used < before.Used {
			res.Freed = int64(before.Used - after.Used) // #nosec G115 -- a volume size fits an int64
		}
	}
	return res, nil
}

// Updates removes what updates leave behind: a held upload (or fetched
// file) nobody staged within the retention, partial uploads and cut-off
// stage work an hour old. Nothing goes while a file is coming in or a
// stage runs.
type Updates struct {
	Uploads, StageDir string
	Retention         time.Duration
	Busy              func() bool
}

// Category implements Step.
func (Updates) Category() string { return CategoryUpdates }

// leftoverAge is how old a partial file must be before it goes.
const leftoverAge = time.Hour

// Clean implements Step.
func (u Updates) Clean(_ context.Context, env Env) (Result, error) {
	if u.Busy != nil && u.Busy() {
		return Result{Note: "an update is coming in or staging; skipped"}, nil
	}
	var freed int64
	remove := func(p string) error {
		n, err := env.Safety.Remove(p)
		freed += n
		if err == nil && n > 0 {
			env.Logger.Info("diskguard: removed an update file left behind", log.F("file", p), log.F("bytes", n))
		}
		return err
	}
	ents, err := os.ReadDir(u.Uploads)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Result{}, fmt.Errorf("diskguard: uploads: %w", err)
	}
	for _, e := range ents {
		p := filepath.Join(u.Uploads, e.Name())
		fi, err := e.Info()
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		age := env.Now.Sub(fi.ModTime())
		switch {
		case strings.HasSuffix(e.Name(), ".tmp") && age >= leftoverAge:
			err = remove(p)
		case strings.HasSuffix(e.Name(), ".bin") && env.Now.Sub(uploadTime(p, fi)) >= u.Retention:
			if err = remove(p); err == nil {
				err = remove(strings.TrimSuffix(p, ".bin") + ".json")
			}
		}
		if err != nil {
			return Result{Freed: freed}, err
		}
	}
	stage, err := os.ReadDir(u.StageDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Result{Freed: freed}, fmt.Errorf("diskguard: stage work: %w", err)
	}
	for _, e := range stage {
		fi, err := e.Info()
		if err != nil || env.Now.Sub(fi.ModTime()) < leftoverAge {
			continue
		}
		if err := remove(filepath.Join(u.StageDir, e.Name())); err != nil {
			return Result{Freed: freed}, err
		}
	}
	return Result{Freed: freed}, nil
}

// uploadTime is when an upload came in: its record's time, else the
// file's.
func uploadTime(bin string, fi fs.FileInfo) time.Time {
	var m struct {
		At time.Time `json:"at"`
	}
	if b, err := os.ReadFile(strings.TrimSuffix(bin, ".bin") + ".json"); err == nil && json.Unmarshal(b, &m) == nil && !m.At.IsZero() { // #nosec G304 -- an upload's own record
		return m.At
	}
	return fi.ModTime()
}

// Tmp removes regular files under Dir not changed for Age.
type Tmp struct {
	Dir string
	Age time.Duration
}

// Category implements Step.
func (Tmp) Category() string { return CategoryTmp }

// Clean implements Step.
func (t Tmp) Clean(_ context.Context, env Env) (Result, error) {
	var freed int64
	err := filepath.WalkDir(t.Dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || p != t.Dir {
				return nil
			}
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		fi, err := d.Info()
		if err != nil || env.Now.Sub(fi.ModTime()) < t.Age {
			return nil
		}
		n, err := env.Safety.Remove(p)
		if err != nil {
			return err
		}
		freed += n
		return nil
	})
	return Result{Freed: freed}, err
}

// WAL checks each watched data path's write-ahead log against its limit.
// It frees nothing: the database keeps its WAL within its own settings
// (max_wal_size in the product's bundle), and no WAL file is ever removed
// by hand. An over-limit WAL is in the note and on Status.
type WAL struct {
	Watches func() []Watch
	DirSize func(string) (int64, error)
}

// Category implements Step.
func (WAL) Category() string { return CategoryWAL }

// Clean implements Step.
func (w WAL) Clean(_ context.Context, _ Env) (Result, error) {
	size := w.DirSize
	if size == nil {
		size = DirSize
	}
	var over []string
	checked := 0
	for _, wt := range w.Watches() {
		if wt.WAL == "" {
			continue
		}
		checked++
		n, err := size(wt.WALPath())
		if err != nil {
			continue
		}
		if wt.WALWarn > 0 && n > wt.WALWarn {
			over = append(over, fmt.Sprintf("%s %s over %s", wt.Name, Bytes(n), Bytes(wt.WALWarn)))
		}
	}
	switch {
	case checked == 0:
		return Result{Note: "no write-ahead log is declared"}, nil
	case len(over) > 0:
		return Result{Note: "over the limit: " + strings.Join(over, ", ")}, nil
	}
	return Result{Note: "within the limit"}, nil
}

// DirSize is the space everything under p takes on disk.
func DirSize(p string) (int64, error) {
	var n int64
	err := filepath.WalkDir(p, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				n += allocated(fi)
			}
		}
		return nil
	})
	return n, err
}

// Bytes is n in binary units, one decimal: 1.5 GiB.
func Bytes(n int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	v, u := float64(n), 0
	for v >= 1024 && u < len(units)-1 {
		v /= 1024
		u++
	}
	if u == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", v, units[u])
}
