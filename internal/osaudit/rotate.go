// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osaudit

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
)

// DefaultMaxFileSize is the size a log file rolls over at.
const DefaultMaxFileSize = 16 << 20

// The entries the log writes about itself.
const (
	// ActionRotate is the first line of a part a full file rolled over to:
	// detail.previous names the file before it, detail.previousLines and
	// detail.previousSha256 are its line count and the SHA-256 of its
	// bytes (uncompressed), which verification checks while that file is
	// on the box.
	ActionRotate = "os-audit.rotate"
	// ActionArchiveExport records archived files moved off the state
	// volume to the export directory: detail.files, detail.bytes,
	// detail.first, detail.last and detail.to.
	ActionArchiveExport = "os-audit.archive.export"
)

// selfActor is the actor of the entries the log writes about itself.
const selfActor = "os-audit"

const (
	gzSuffix  = ".gz"
	partMark  = ".p"
	flagsName = ".archive-flags.json"
)

// keyOf is a file's name in chain order: the name with any .gz left off.
func keyOf(name string) string { return strings.TrimSuffix(name, gzSuffix) }

// dayOf is the UTC day a file belongs to, as YYYY-MM-DD.
func dayOf(name string) string {
	k := strings.TrimSuffix(strings.TrimPrefix(keyOf(name), filePrefix), fileSuffix)
	day, _, _ := strings.Cut(k, ".")
	return day
}

// nextPart is the part after key: log-<day>.jsonl rolls to
// log-<day>.p0001.jsonl, which rolls to .p0002 and so on. The parts sort
// after the day's first file and before the next day's.
func nextPart(key string) string {
	base := strings.TrimSuffix(key, fileSuffix)
	n := 0
	if i := strings.LastIndex(base, partMark); i >= 0 {
		if v, err := strconv.Atoi(base[i+len(partMark):]); err == nil {
			n, base = v, base[:i]
		}
	}
	return fmt.Sprintf("%s%s%04d%s", base, partMark, n+1, fileSuffix)
}

// target is the file an entry at t goes to: the day's file, or the newest
// file when the clock is behind it, or the newest file's next part when
// that one is full (or already compressed). rolled reports a new part.
func (l *Log) target(t time.Time) (name string, rolled bool) {
	day := filepath.Base(l.pathFor(t))
	if l.newest == "" {
		return day, false
	}
	cur := keyOf(l.newest)
	if day > cur {
		return day, false
	}
	if l.newest == cur && l.size < l.o.MaxFileSize {
		return cur, false
	}
	return nextPart(cur), true
}

// writeLink starts the part name with the rotation entry naming the file
// before it; the caller holds the locks.
func (l *Log) writeLink(name string, t time.Time) error {
	b, err := l.readFile(l.newest)
	if err != nil {
		return err
	}
	sum := sumOf(b)
	prev := keyOf(l.newest)
	l.o.Logger.Info("os audit: the log file is full; rolling over", log.F("from", prev), log.F("to", name), log.F("bytes", len(b)))
	return l.appendTo(name, Entry{Time: t, Actor: selfActor, Action: ActionRotate, Outcome: "ok",
		Detail: map[string]string{"previous": prev, "previousLines": strconv.Itoa(sum.lines), "previousSha256": sum.sha}})
}

type fileSum struct {
	sha   string
	lines int
}

func sumOf(b []byte) fileSum {
	s := sha256.Sum256(b)
	return fileSum{sha: hex.EncodeToString(s[:]), lines: bytes.Count(b, []byte("\n"))}
}

// checkLink checks a rotation entry against the file it names, when that
// file is still on the box (an exported or pruned one isn't).
func checkLink(name string, e Entry, seen map[string]fileSum) error {
	sum, ok := seen[e.Detail["previous"]]
	if !ok {
		return nil
	}
	if sum.sha != e.Detail["previousSha256"] || strconv.Itoa(sum.lines) != e.Detail["previousLines"] {
		return fmt.Errorf("os audit: %s's first line doesn't match %s, the file before it", name, e.Detail["previous"])
	}
	return nil
}

// readFile reads a log file, decompressing a .gz one.
func (l *Log) readFile(name string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(l.dir, name)) // #nosec G304 -- a file listed from the log directory
	if err != nil {
		return nil, fmt.Errorf("os audit: %w", err)
	}
	if !strings.HasSuffix(name, gzSuffix) {
		return b, nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("os audit: %s: %w", name, err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("os audit: %s: %w", name, err)
	}
	return out, nil
}

// ReadFiles hands fn every file, oldest first, decompressed: the log as
// written, so the chain verifies off the box too. name is the file's name
// without any .gz.
func (l *Log) ReadFiles(fn func(name string, r io.Reader) error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	files, err := l.files()
	if err != nil {
		return err
	}
	for _, name := range files {
		b, err := l.readFile(name)
		if err != nil {
			return err
		}
		if err := fn(keyOf(name), bytes.NewReader(b)); err != nil {
			return err
		}
	}
	return nil
}

// CompressResult is what a compress did.
type CompressResult struct {
	// Files is how many files were compressed; Freed the bytes that gave
	// back (never below 0).
	Files int
	Freed int64
}

// Compress archives every file but the newest as .jsonl.gz: written
// beside it, read back and checked against it, then the plain file goes.
// Nothing is dropped; the chain reads the same.
func (l *Log) Compress() (CompressResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	unlock, err := l.lock()
	if err != nil {
		return CompressResult{}, err
	}
	defer unlock()
	if err := l.refresh(); err != nil {
		return CompressResult{}, err
	}
	files, err := l.files()
	if err != nil {
		return CompressResult{}, err
	}
	var res CompressResult
	for _, name := range files {
		if name == l.newest || strings.HasSuffix(name, gzSuffix) {
			continue
		}
		freed, err := l.compressOne(name)
		if err != nil {
			return res, err
		}
		res.Files++
		res.Freed += freed
	}
	res.Freed = max(res.Freed, 0)
	if res.Files > 0 {
		l.o.Logger.Info("os audit: compressed closed files", log.F("files", res.Files), log.F("freed", res.Freed))
	}
	return res, nil
}

func (l *Log) compressOne(name string) (int64, error) {
	src := filepath.Join(l.dir, name)
	plain, err := os.ReadFile(src) // #nosec G304 -- a file listed from the log directory
	if err != nil {
		return 0, fmt.Errorf("os audit: %w", err)
	}
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if _, err := zw.Write(plain); err != nil {
		return 0, fmt.Errorf("os audit: %w", err)
	}
	if err := zw.Close(); err != nil {
		return 0, fmt.Errorf("os audit: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		return 0, fmt.Errorf("os audit: %w", err)
	}
	back, err := io.ReadAll(zr)
	if err != nil || !bytes.Equal(back, plain) {
		return 0, fmt.Errorf("os audit: %s doesn't read back the same compressed; left as it is", name)
	}
	if err := writeSynced(src+gzSuffix, buf.Bytes()); err != nil {
		return 0, err
	}
	if err := os.Remove(src); err != nil {
		return 0, fmt.Errorf("os audit: %w", err)
	}
	syncDir(l.dir)
	l.o.Logger.Debug("os audit: compressed", log.F("file", name), log.F("from", len(plain)), log.F("to", buf.Len()))
	return int64(len(plain) - buf.Len()), nil
}

// writeSynced writes b to p through a synced temporary file and a rename.
func writeSynced(p string, b []byte) error {
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- a file in the log or export directory
	if err != nil {
		return fmt.Errorf("os audit: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("os audit: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("os audit: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("os audit: %w", err)
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("os audit: %w", err)
	}
	return nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil { // #nosec G304 -- the log or export directory
		_ = d.Sync()
		_ = d.Close()
	}
}

// ArchiveOptions bound the archive: the closed files, all but the newest.
type ArchiveOptions struct {
	// MaxBytes and MaxFiles are the archive's caps; 0 is no cap.
	MaxBytes int64
	MaxFiles int
	// Grace is how long the oldest files stay flagged, with a warning,
	// before they move.
	Grace time.Duration
	// ExportDir is where they move to: on another volume (the backup
	// volume on the box), never the state volume itself.
	ExportDir string
}

// ArchiveReport is what an archive check found and did.
type ArchiveReport struct {
	// Flagged are the files over the caps waiting to move, oldest first,
	// FlaggedBytes their size, and ExportAfter when the first of them may.
	Flagged      []string
	FlaggedBytes int64
	ExportAfter  time.Time
	// Exported are the files this check moved to the export directory,
	// and Freed the bytes that gave back.
	Exported []string
	Freed    int64
}

// Archive keeps the archive within its caps without silently dropping
// anything: the oldest files over the caps are flagged first, and each
// moves to the export directory only once it has been flagged for the
// grace period, copied, synced and checked byte for byte before it's
// removed here. The move is audited. A file that can't move stays, still
// flagged, and the error says why.
func (l *Log) Archive(o ArchiveOptions) (ArchiveReport, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	unlock, err := l.lock()
	if err != nil {
		return ArchiveReport{}, err
	}
	defer unlock()
	if err := l.refresh(); err != nil {
		return ArchiveReport{}, err
	}
	files, err := l.files()
	if err != nil {
		return ArchiveReport{}, err
	}
	var closed []string
	sizes := map[string]int64{}
	var total int64
	for _, n := range files {
		if n == l.newest {
			continue
		}
		closed = append(closed, n)
		sizes[n] = fileSize(filepath.Join(l.dir, n))
		total += sizes[n]
	}
	var over []string
	for _, n := range closed {
		count := len(closed) - len(over)
		if (o.MaxBytes <= 0 || total <= o.MaxBytes) && (o.MaxFiles <= 0 || count <= o.MaxFiles) {
			break
		}
		over = append(over, n)
		total -= sizes[n]
	}
	now := l.o.Now().UTC()
	old := l.readFlags()
	flags := map[string]time.Time{}
	for _, n := range over {
		at, ok := old[n]
		if !ok {
			at = now
			l.o.Logger.Warn("os audit: the archive is over its cap; flagged to move", log.F("file", n), log.F("after", now.Add(o.Grace).Format(time.RFC3339)))
		}
		flags[n] = at
	}
	var rep ArchiveReport
	var moveErr error
	for _, n := range over {
		if moveErr == nil && !now.Before(flags[n].Add(o.Grace)) {
			if err := l.export(n, o.ExportDir); err != nil {
				moveErr = err
				l.o.Logger.Error(err, "os audit: an archived file didn't move; it stays", log.F("file", n))
			} else {
				rep.Exported = append(rep.Exported, n)
				rep.Freed += sizes[n]
				delete(flags, n)
				continue
			}
		}
		rep.Flagged = append(rep.Flagged, n)
		rep.FlaggedBytes += sizes[n]
		if at := flags[n].Add(o.Grace); rep.ExportAfter.IsZero() || at.Before(rep.ExportAfter) {
			rep.ExportAfter = at
		}
	}
	l.writeFlags(flags)
	if len(rep.Exported) > 0 {
		e := Entry{Actor: selfActor, Action: ActionArchiveExport, Outcome: "ok", Detail: map[string]string{
			"files": strconv.Itoa(len(rep.Exported)), "bytes": strconv.FormatInt(rep.Freed, 10),
			"first": keyOf(rep.Exported[0]), "last": keyOf(rep.Exported[len(rep.Exported)-1]), "to": o.ExportDir,
		}}
		if err := l.appendLocked(e); err != nil {
			return rep, err
		}
		l.o.Logger.Info("os audit: archived files moved off the state volume", log.F("files", len(rep.Exported)), log.F("to", o.ExportDir))
	}
	return rep, moveErr
}

// export copies the file name to dir, checks the copy and removes the
// original.
func (l *Log) export(name, dir string) error {
	if dir == "" {
		return errors.New("os audit: no export directory is set")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("os audit: %w", err)
	}
	src := filepath.Join(l.dir, name)
	b, err := os.ReadFile(src) // #nosec G304 -- a file listed from the log directory
	if err != nil {
		return fmt.Errorf("os audit: %w", err)
	}
	dst := filepath.Join(dir, name)
	if err := writeSynced(dst, b); err != nil {
		return err
	}
	syncDir(dir)
	back, err := os.ReadFile(dst) // #nosec G304 -- the copy just written
	if err != nil || !bytes.Equal(back, b) {
		return fmt.Errorf("os audit: the copy of %s in %s doesn't match; the file stays", name, dir)
	}
	if err := os.Remove(src); err != nil {
		return fmt.Errorf("os audit: %w", err)
	}
	syncDir(l.dir)
	return nil
}

func (l *Log) readFlags() map[string]time.Time {
	out := map[string]time.Time{}
	b, err := os.ReadFile(filepath.Join(l.dir, flagsName)) // #nosec G304 -- the log's own file
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			l.o.Logger.Warn("os audit: the archive flags don't read", log.F("error", err.Error()))
		}
		return out
	}
	if err := json.Unmarshal(b, &out); err != nil {
		l.o.Logger.Warn("os audit: the archive flags don't parse; flagging again", log.F("error", err.Error()))
		return map[string]time.Time{}
	}
	return out
}

func (l *Log) writeFlags(flags map[string]time.Time) {
	p := filepath.Join(l.dir, flagsName)
	if len(flags) == 0 {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			l.o.Logger.Warn("os audit: the archive flags weren't cleared", log.F("error", err.Error()))
		}
		return
	}
	b, _ := json.Marshal(flags)
	if err := writeSynced(p, b); err != nil {
		l.o.Logger.Warn("os audit: the archive flags weren't saved", log.F("error", err.Error()))
	}
}

// ActionPrune records a file removed for retention, once the archive held
// it: detail.file, detail.sha256 and detail.lines (its bytes uncompressed),
// detail.lastLineSha256 (its chain link: the hash the next file's first
// line chains to), detail.reason, detail.archived (the copy's path) and
// detail.copied (yes when this prune copied it, no when it was there).
const ActionPrune = "os-audit.prune"

// PruneBlock is a file past retention that stays, and why.
type PruneBlock struct {
	File, Reason string
}

// PruneBlocked are the files the last Prune kept because the archive
// couldn't take them.
func (l *Log) PruneBlocked() []PruneBlock {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]PruneBlock(nil), l.blocked...)
}

// pruneOne archives the file name, removes it and audits the removal; the
// caller holds the locks.
func (l *Log) pruneOne(name, reason string) error {
	src := filepath.Join(l.dir, name)
	raw, err := os.ReadFile(src) // #nosec G304 -- a file listed from the log directory
	if err != nil {
		return fmt.Errorf("os audit: %w", err)
	}
	plain, err := l.readFile(name)
	if err != nil {
		return err
	}
	dst, copied, err := l.archiveCopy(name, raw)
	if err != nil {
		return err
	}
	sum := sumOf(plain)
	last := ""
	if lines := bytes.Split(bytes.TrimRight(plain, "\n"), []byte("\n")); len(lines[len(lines)-1]) > 0 {
		last = hashLine(lines[len(lines)-1])
	}
	if err := os.Remove(src); err != nil {
		return fmt.Errorf("os audit: %w", err)
	}
	if name == keyOf(name) {
		_ = os.Remove(src + gzSuffix)
	}
	syncDir(l.dir)
	l.o.Logger.Info("os audit: pruned log file", log.F("file", name), log.F("archived", dst), log.F("copied", copied))
	return l.appendLocked(Entry{Actor: selfActor, Action: ActionPrune, Target: "OS audit log file", Outcome: "ok", Detail: map[string]string{
		"file": keyOf(name), "sha256": sum.sha, "lines": strconv.Itoa(sum.lines), "lastLineSha256": last,
		"reason": reason, "archived": dst, "copied": map[bool]string{true: "yes", false: "no"}[copied],
	}})
}

// archiveCopy makes sure the archive holds raw as name: there already, or
// copied, synced and read back. A different file of that name there is an
// error; nothing is overwritten.
func (l *Log) archiveCopy(name string, raw []byte) (string, bool, error) {
	if l.o.ArchiveDir == "" {
		return "", false, errors.New("os audit: no archive directory is set")
	}
	dst := filepath.Join(l.o.ArchiveDir, name)
	if have, err := os.ReadFile(dst); err == nil { // #nosec G304 -- the archive's copy of a log file
		if !bytes.Equal(have, raw) {
			return "", false, fmt.Errorf("os audit: the archive holds a different %s", name)
		}
		return dst, false, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", false, fmt.Errorf("os audit: %w", err)
	}
	if err := os.MkdirAll(l.o.ArchiveDir, 0o700); err != nil {
		return "", false, fmt.Errorf("os audit: %w", err)
	}
	if err := writeSynced(dst, raw); err != nil {
		return "", false, err
	}
	syncDir(l.o.ArchiveDir)
	back, err := os.ReadFile(dst) // #nosec G304 -- the copy just written
	if err != nil || !bytes.Equal(back, raw) {
		return "", false, fmt.Errorf("os audit: the archive's copy of %s doesn't match", name)
	}
	return dst, true, nil
}
