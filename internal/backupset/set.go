// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package backupset

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// ManifestFile is a set's description; it's written last, so a directory
// without one isn't a set.
const ManifestFile = "manifest.json"

const (
	// tmpPrefix marks a set being made; the next one clears it.
	tmpPrefix = ".tmp-"
	storeName = "store"
	// baseBound and archiveBound bound the waits for a base backup and for
	// the restore point's segment to reach the archive.
	baseBound = 6 * time.Hour
	// baseAskAgain is how long the box waits before it asks for the base
	// backup again. A cluster killed under one records nothing, and a
	// request it can't take yet is one it takes next.
	baseAskAgain = 15 * time.Minute
	archiveBound = 5 * time.Minute
)

// Engine reaches the running cluster. Cluster is the box's kubectl; the
// tests use a real PostgreSQL or a fake.
type Engine interface {
	// RestorePoint makes the named restore point, closes its WAL segment
	// and answers where it is.
	RestorePoint(ctx context.Context, b productspec.Backups, point string) (lsn string, timeline uint32, err error)
	// RequestBase asks the cluster for a base backup now.
	RequestBase(ctx context.Context, b productspec.Backups) error
	// Annotations reads the status Lease.
	Annotations(ctx context.Context, b productspec.Backups) (map[string]string, error)
	// KeyDigest is the digest of a product key; never the key.
	KeyDigest(ctx context.Context, k productspec.EscrowKey) (string, error)
}

// Manager makes and lists a product's backup sets.
type Manager struct {
	// Spec reads the installed product's declaration; nil backups means the
	// product has none.
	Spec   func() (productspec.Spec, error)
	Engine Engine
	// Recipients are the box's recovery keys, for an export.
	Recipients func() ([]string, error)
	Audit      func(action string, detail map[string]string)
	Logger     log.Logger
	// Every is how often a wait looks again; 0 is 2 seconds.
	Every time.Duration
	Now   func() time.Time

	mu sync.Mutex
}

// File is one file of a set.
type File struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Manifest describes a set. It holds no secret and no row.
type Manifest struct {
	Format int    `json:"format"`
	Name   string `json:"name"`
	// Point is the named restore point the set restores to, at LSN on
	// Timeline.
	Point    string    `json:"point"`
	LSN      string    `json:"lsn"`
	Timeline uint32    `json:"timeline"`
	Taken    time.Time `json:"taken"`
	Base     string    `json:"base"`
	// PGVersion and SystemID are the cluster's.
	PGVersion int    `json:"pg_version"`
	SystemID  string `json:"system_id"`
	// Keys are the digests of the product keys the data needs: only a box
	// holding the same keys restores this set.
	Keys map[string]string `json:"keys"`
	// Uncompressed is the base backup's size once restored.
	Uncompressed int64  `json:"uncompressed"`
	Bytes        int64  `json:"bytes"`
	Files        []File `json:"files"`
}

// Set is a set in a listing.
type Set struct {
	Name, Point string
	Taken       time.Time
	Bytes       int64
}

func (m *Manager) logger() log.Logger {
	if m.Logger == nil {
		return log.Nop()
	}
	return m.Logger
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func (m *Manager) every() time.Duration {
	if m.Every > 0 {
		return m.Every
	}
	return 2 * time.Second
}

func (m *Manager) audit(action string, detail map[string]string) {
	if m.Audit != nil {
		m.Audit(action, detail)
	}
}

func (m *Manager) backups() (productspec.Spec, productspec.Backups, error) {
	s, err := m.Spec()
	if err != nil {
		return s, productspec.Backups{}, err
	}
	if s.Backups == nil {
		return s, productspec.Backups{}, codes.New(codes.BackupSet, "the installed product declares no backups")
	}
	return s, *s.Backups, nil
}

var setNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// CheckName refuses a name a set can't have.
func CheckName(name string) error {
	if !setNameRE.MatchString(name) {
		return codes.New(codes.BackupSet, "%q can't name a backup set: use lower-case letters, digits and hyphens", name)
	}
	return nil
}

// Create cuts a set: a base backup and the WAL up to a new restore point,
// linked out of the archive, so retention can't take it and it costs no copy.
// An empty name makes one from the time. The product keeps running.
func (m *Manager) Create(ctx context.Context, name string) (Manifest, error) {
	if !m.mu.TryLock() {
		return Manifest{}, codes.New(codes.BackupBusy, "another backup set is being made")
	}
	defer m.mu.Unlock()
	spec, b, err := m.backups()
	if err != nil {
		return Manifest{}, err
	}
	start := m.now()
	if name == "" {
		name = "set-" + strings.ToLower(start.Format("20060102t150405z"))
	}
	if err := CheckName(name); err != nil {
		return Manifest{}, err
	}
	dir := filepath.Join(b.SetsHostDir(), name)
	if _, err := os.Stat(dir); err == nil {
		return Manifest{}, codes.New(codes.BackupSet, "there's already a backup set %s", name)
	}
	m.logger().Info("backupset: a set starts", log.F("set", name))
	keys := map[string]string{}
	for _, k := range spec.Escrow {
		if keys[k.Name], err = m.Engine.KeyDigest(ctx, k); err != nil {
			return Manifest{}, codes.New(codes.Backup, "the product key %s doesn't read: %v", k.Name, err)
		}
	}
	store := b.StoreHostDir()
	if have, err := bases(store); err != nil {
		return Manifest{}, codes.Wrap(codes.Backup, err)
	} else if len(have) == 0 {
		if err := m.freshBase(ctx, b, ""); err != nil {
			return Manifest{}, err
		}
	}
	point := name + "-" + strings.ToLower(start.Format("20060102t150405z"))
	bb, files, lsn, tl, err := m.reachPoint(ctx, b, point)
	if _, coded := codes.Of(err); err != nil && coded {
		return Manifest{}, err
	}
	if err != nil {
		// A gap in the archive only a new base backup closes: one taken
		// after it, and a point after that.
		m.logger().Warn("backupset: the archive doesn't reach the point from the newest base backup; taking a new one", log.F("set", name), log.F("why", err.Error()))
		newest, berr := bases(store)
		if berr != nil {
			return Manifest{}, codes.Wrap(codes.Backup, berr)
		}
		if len(newest) == 0 {
			return Manifest{}, codes.New(codes.Backup, "the archive holds no base backup")
		}
		if err := m.freshBase(ctx, b, newest[len(newest)-1].Name); err != nil {
			return Manifest{}, err
		}
		if bb, files, lsn, tl, err = m.reachPoint(ctx, b, point+"-2"); err != nil {
			return Manifest{}, codes.New(codes.Backup, "the archive doesn't reach the restore point: %v", err)
		}
		point += "-2"
	}
	mf := Manifest{Format: 1, Name: name, Point: point, LSN: lsn, Timeline: tl, Taken: m.now(), Base: bb.Name,
		PGVersion: bb.PGVersion, SystemID: strconv.FormatUint(bb.SystemID, 10), Keys: keys, Uncompressed: bb.Uncompressed}
	if err := m.write(b, &mf, bb, files); err != nil {
		return Manifest{}, err
	}
	m.audit("product.backup.create", map[string]string{"set": name, "point": point, "bytes": strconv.FormatInt(mf.Bytes, 10)})
	m.logger().Info("backupset: a set is done", log.F("set", name), log.F("point", point), log.F("base", bb.Name), log.F("bytes", mf.Bytes), log.F("seconds", int(m.now().Sub(start).Seconds())))
	return mf, nil
}

// reachPoint makes the restore point and answers the newest base backup with
// every WAL file from it to the point.
func (m *Manager) reachPoint(ctx context.Context, b productspec.Backups, point string) (base, []string, string, uint32, error) {
	lsn, tl, err := m.Engine.RestorePoint(ctx, b, point)
	if err != nil {
		return base{}, nil, "", 0, codes.New(codes.Backup, "the restore point wasn't made: %v", err)
	}
	at, err := parseLSN(lsn)
	if err != nil {
		return base{}, nil, "", 0, codes.Wrap(codes.Backup, err)
	}
	// The LSN is the end of the point's record, which can be the start of
	// the next segment; the record is in the one before it.
	at--
	store := b.StoreHostDir()
	seg := segmentName(tl, segmentNo(at))
	deadline := m.now().Add(archiveBound)
	for {
		have, err := segments(store)
		if err != nil {
			return base{}, nil, "", 0, codes.Wrap(codes.Backup, err)
		}
		if _, ok := have[seg]; ok {
			break
		}
		if m.now().After(deadline) {
			return base{}, nil, "", 0, codes.New(codes.Backup, "the restore point's WAL hasn't reached the archive after %s: is the backup partition full?", archiveBound)
		}
		if err := sleep(ctx, m.every()); err != nil {
			return base{}, nil, "", 0, err
		}
	}
	all, err := bases(store)
	if err != nil {
		return base{}, nil, "", 0, codes.Wrap(codes.Backup, err)
	}
	if len(all) == 0 {
		return base{}, nil, "", 0, errors.New("no base backup")
	}
	bb := all[len(all)-1]
	have, err := segments(store)
	if err != nil {
		return base{}, nil, "", 0, codes.Wrap(codes.Backup, err)
	}
	files, err := chain(have, bb, tl, at)
	return bb, files, lsn, tl, err
}

// freshBase asks for a base backup newer than after and waits for it.
func (m *Manager) freshBase(ctx context.Context, b productspec.Backups, after string) error {
	before, err := m.Engine.Annotations(ctx, b)
	if err != nil {
		return codes.New(codes.Backup, "the cluster's backup status doesn't read: %v", err)
	}
	failed := before[b.Status.Failure]
	if err := m.Engine.RequestBase(ctx, b); err != nil {
		return codes.New(codes.Backup, "the base backup wasn't asked for: %v", err)
	}
	deadline, again := m.now().Add(baseBound), m.now().Add(baseAskAgain)
	for {
		all, err := bases(b.StoreHostDir())
		if err != nil {
			return codes.Wrap(codes.Backup, err)
		}
		if len(all) > 0 && all[len(all)-1].Name != after {
			return nil
		}
		if a, err := m.Engine.Annotations(ctx, b); err == nil && a[b.Status.Failure] != failed {
			return codes.New(codes.BackupRoom, "the base backup failed at %s: the backup partition may be full", a[b.Status.Failure])
		}
		if m.now().After(deadline) {
			return codes.New(codes.Backup, "no base backup after %s", baseBound)
		}
		if m.now().After(again) {
			again = m.now().Add(baseAskAgain)
			m.logger().Warn("backupset: no base backup yet; asking again")
			if err := m.Engine.RequestBase(ctx, b); err != nil {
				m.logger().Warn("backupset: the base backup wasn't asked for again", log.F("error", err.Error()))
			}
		}
		if err := sleep(ctx, m.every()); err != nil {
			return err
		}
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// write links the set into place and writes its manifest. The set appears in
// one rename, so a set cut off leaves only a .tmp- directory.
func (m *Manager) write(b productspec.Backups, mf *Manifest, bb base, wal []string) error {
	sets := b.SetsHostDir()
	if err := os.MkdirAll(sets, 0o755); err != nil { // #nosec G301 -- the pods read the sets; the mount above is 0700
		return codes.Wrap(codes.Backup, err)
	}
	if err := clearTmp(sets); err != nil {
		return codes.Wrap(codes.Backup, err)
	}
	tmp := filepath.Join(sets, tmpPrefix+mf.Name)
	dst := filepath.Join(tmp, storeName)
	store := b.StoreHostDir()
	if err := linkTree(filepath.Join(store, baseDir, bb.Name), filepath.Join(dst, baseDir, bb.Name)); err != nil {
		return codes.Wrap(codes.Backup, err)
	}
	if err := linkFile(filepath.Join(store, baseDir, bb.Name+sentinelSuffix), filepath.Join(dst, baseDir, bb.Name+sentinelSuffix)); err != nil {
		return codes.Wrap(codes.Backup, err)
	}
	extra, err := walExtras(store, bb, wal)
	if err != nil {
		return codes.Wrap(codes.Backup, err)
	}
	for _, f := range append(slices.Clone(wal), extra...) {
		if err := linkFile(filepath.Join(store, walDir, f), filepath.Join(dst, walDir, f)); err != nil {
			return codes.Wrap(codes.Backup, err)
		}
	}
	if err := measure(tmp, mf); err != nil {
		return codes.Wrap(codes.Backup, err)
	}
	body, err := json.MarshalIndent(mf, "", "  ")
	if err != nil {
		return codes.Wrap(codes.Backup, err)
	}
	if err := writeSynced(filepath.Join(tmp, ManifestFile), body); err != nil {
		return codes.Wrap(codes.Backup, err)
	}
	if err := os.Rename(tmp, filepath.Join(sets, mf.Name)); err != nil {
		return codes.Wrap(codes.Backup, err)
	}
	return syncDir(sets)
}

// walExtras are the timeline histories and the base backup's history file,
// which a restore reads beside the segments.
func walExtras(store string, bb base, wal []string) ([]string, error) {
	ents, err := os.ReadDir(filepath.Join(store, walDir))
	if err != nil {
		return nil, err
	}
	first := strings.SplitN(wal[0], ".", 2)[0]
	var out []string
	for _, e := range ents {
		n := e.Name()
		switch {
		case strings.Contains(n, tmpMark):
		case strings.Contains(n, ".history"):
			out = append(out, n)
		case strings.HasPrefix(n, first+".") && strings.Contains(n, ".backup"):
			out = append(out, n)
		}
	}
	return out, nil
}

func clearTmp(sets string) error {
	ents, err := os.ReadDir(sets)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), tmpPrefix) {
			if err := os.RemoveAll(filepath.Join(sets, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func linkFile(from, to string) error {
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil { // #nosec G301 -- as the sets directory
		return err
	}
	return os.Link(from, to)
}

func linkTree(from, to string) error {
	return filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, p)
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(to, rel), 0o755) // #nosec G301 -- as the sets directory
		}
		return linkFile(p, filepath.Join(to, rel))
	})
}

// measure records every file's size and digest. Reading them all is also the
// first proof they're whole.
func measure(dir string, mf *Manifest) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		sum, n, err := digestFile(p)
		if err != nil {
			return err
		}
		mf.Files = append(mf.Files, File{Path: filepath.ToSlash(rel), Bytes: n, SHA256: sum})
		mf.Bytes += n
		return nil
	})
}

func digestFile(p string) (string, int64, error) {
	f, err := os.Open(p) // #nosec G304 -- a file of the box's own set
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}

func writeSynced(p string, b []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644) // #nosec G302 G304 -- no secret; the box's own set
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	return errors.Join(werr, f.Sync(), f.Close())
}

func syncDir(p string) error {
	d, err := os.Open(p) // #nosec G304 -- the box's own directory
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

// ReadManifest reads the named set's manifest.
func ReadManifest(b productspec.Backups, name string) (Manifest, error) {
	if err := CheckName(name); err != nil {
		return Manifest{}, err
	}
	raw, err := os.ReadFile(filepath.Join(b.SetsHostDir(), name, ManifestFile)) // #nosec G304 -- name passed CheckName
	if errors.Is(err, fs.ErrNotExist) {
		return Manifest{}, codes.New(codes.BackupSet, "there's no backup set %s", name)
	}
	if err != nil {
		return Manifest{}, codes.Wrap(codes.Backup, err)
	}
	var mf Manifest
	if err := json.Unmarshal(raw, &mf); err != nil {
		return Manifest{}, codes.New(codes.Backup, "the manifest of %s doesn't read: %v", name, err)
	}
	if mf.Name != name {
		return Manifest{}, codes.New(codes.BackupSet, "the directory %s holds the set %s", name, mf.Name)
	}
	return mf, nil
}

// Verify reads every file of a set and compares it with the manifest.
func Verify(b productspec.Backups, mf Manifest) error {
	dir := filepath.Join(b.SetsHostDir(), mf.Name)
	for _, f := range mf.Files {
		sum, n, err := digestFile(filepath.Join(dir, filepath.FromSlash(f.Path)))
		if err != nil {
			return fmt.Errorf("%s: %w", f.Path, err)
		}
		if n != f.Bytes || sum != f.SHA256 {
			return fmt.Errorf("%s isn't what the set holds", f.Path)
		}
	}
	return nil
}

// List lists the sets, oldest first. One whose manifest doesn't read is left
// out and logged.
func (m *Manager) List() ([]Set, error) {
	_, b, err := m.backups()
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(b.SetsHostDir())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, codes.Wrap(codes.Backup, err)
	}
	var out []Set
	for _, e := range ents {
		if !e.IsDir() || strings.HasPrefix(e.Name(), tmpPrefix) {
			continue
		}
		mf, err := ReadManifest(b, e.Name())
		if err != nil {
			m.logger().Warn("backupset: a set doesn't read", log.F("set", e.Name()), log.F("error", err.Error()))
			continue
		}
		out = append(out, Set{Name: mf.Name, Point: mf.Point, Taken: mf.Taken, Bytes: mf.Bytes})
	}
	slices.SortFunc(out, func(a, c Set) int { return a.Taken.Compare(c.Taken) })
	return out, nil
}

// Remove removes a set for good.
func (m *Manager) Remove(name string) error {
	_, b, err := m.backups()
	if err != nil {
		return err
	}
	if _, err := ReadManifest(b, name); err != nil {
		return err
	}
	if err := os.RemoveAll(filepath.Join(b.SetsHostDir(), name)); err != nil {
		return codes.Wrap(codes.Backup, err)
	}
	m.audit("product.backup.remove", map[string]string{"set": name})
	return nil
}
