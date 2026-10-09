// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package webslots keeps the Base Web unit (spec 7): the :8443 admin pages
// in an A/B pair of slot directories on the state volume, with the links
// current, staged and previous between them, the product slots' pattern.
// A slot holds
//
//	pages/          the static files
//	web.yaml        version, commit, requires, and every file's path, size and SHA-256
//	web.yaml.sig    a Sigstore bundle over web.yaml, by the channel's release key
//	header.json     the verified .bin header, written last; a slot without it is never used
//
// Nothing from a slot runs on the box. Every load checks the signature
// against the release key in the running root, reads every listed file and
// checks its SHA-256, and refuses any other file, a link or a path outside
// pages/; the set is then served from memory, so what's on disk later
// can't change what's served until the next load, which checks again.
package webslots

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing/fstest"

	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sigbundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

// Dir is the web slots' directory on the box.
const Dir = "/var/lib/sneakers/web"

// A slot's files.
const (
	PagesDir     = "pages"
	ManifestFile = "web.yaml"
	SigFile      = "web.yaml.sig"
	HeaderFile   = "header.json"
)

// The manifest's fixed fields.
const (
	APIVersion = "sneakers-pam/v1alpha1"
	Kind       = "Web"
)

// Bounds on what a load reads.
const (
	maxManifest = 4 << 20
	maxFiles    = 4096
	maxTotal    = 128 << 20
)

const (
	linkCurrent  = "current"
	linkStaged   = "staged"
	linkPrevious = "previous"
)

var slotNames = []string{"a", "b"}

// Manifest is web.yaml.
type Manifest struct {
	APIVersion string                             `yaml:"apiVersion" json:"apiVersion"`
	Kind       string                             `yaml:"kind" json:"kind"`
	Version    string                             `yaml:"version" json:"version"`
	Commit     string                             `yaml:"commit,omitempty" json:"commit,omitempty"`
	Requires   map[updatepkg.Unit]updatepkg.Range `yaml:"requires,omitempty" json:"requires,omitempty"`
	Files      []File                             `yaml:"files" json:"files"`
}

// File is one page file, by its path under pages/.
type File struct {
	Path   string `yaml:"path" json:"path"`
	Size   int64  `yaml:"size" json:"size"`
	SHA256 string `yaml:"sha256" json:"sha256"`
}

// Pages is a loaded, checked page set, held in memory.
type Pages struct {
	Manifest Manifest
	FS       fs.FS
}

// loadErr is UPGRADE_WEB_LOAD.
func loadErr(format string, args ...any) error {
	return codes.New(codes.UpgradeWebLoad, format, args...)
}

// WriteManifest lists every file under pages (a built page set) in a
// manifest for version and commit, needing the Base OS range need, and
// returns its bytes: what the build signs as web.yaml.
func WriteManifest(pages, version, commit string, need *updatepkg.Range) ([]byte, error) {
	m := Manifest{APIVersion: APIVersion, Kind: Kind, Version: version, Commit: commit}
	if need != nil {
		m.Requires = map[updatepkg.Unit]updatepkg.Range{updatepkg.UnitBaseOS: *need}
	}
	err := filepath.WalkDir(pages, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("webslots: %s isn't a regular file", p)
		}
		b, err := os.ReadFile(p) // #nosec G304 -- a build input
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(pages, p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		m.Files = append(m.Files, File{Path: filepath.ToSlash(rel), Size: int64(len(b)), SHA256: hex.EncodeToString(sum[:])})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !hasIndex(m) {
		return nil, fmt.Errorf("webslots: %s has no index.html", pages)
	}
	return yaml.Marshal(m)
}

func hasIndex(m Manifest) bool {
	for _, f := range m.Files {
		if f.Path == "index.html" {
			return true
		}
	}
	return false
}

// Load reads and checks the slot (or unpacked payload) at dir: web.yaml's
// signature by key, then every file under pages/ against it. Anything
// that doesn't check out is UPGRADE_WEB_LOAD.
func Load(dir string, key *ecdsa.PublicKey) (*Pages, error) {
	raw, err := readCapped(filepath.Join(dir, ManifestFile), maxManifest)
	if err != nil {
		return nil, loadErr("the pages' %s can't be read: %v", ManifestFile, err)
	}
	sig, err := readCapped(filepath.Join(dir, SigFile), 1<<20)
	if err != nil {
		return nil, loadErr("the pages' %s can't be read: %v", SigFile, err)
	}
	bd, err := sigbundle.Parse(sig)
	if err != nil {
		return nil, loadErr("the pages' signature doesn't parse: %v", err)
	}
	if err := bd.Verify(key, sha256.Sum256(raw)); err != nil {
		return nil, loadErr("the pages' %s isn't signed by this box's release key", ManifestFile)
	}
	var m Manifest
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, loadErr("the pages' %s doesn't parse: %v", ManifestFile, err)
	}
	if m.APIVersion != APIVersion || m.Kind != Kind || m.Version == "" || len(m.Files) == 0 || len(m.Files) > maxFiles || !hasIndex(m) {
		return nil, loadErr("the pages' %s isn't a %s %s with an index.html", ManifestFile, APIVersion, Kind)
	}
	listed := map[string]File{}
	for _, f := range m.Files {
		clean := path.Clean(f.Path)
		if f.Path == "" || clean != f.Path || path.IsAbs(f.Path) || strings.HasPrefix(clean, "../") || clean == ".." || strings.Contains(f.Path, "\\") {
			return nil, loadErr("the pages list %q, a path outside pages/", f.Path)
		}
		if _, dup := listed[f.Path]; dup {
			return nil, loadErr("the pages list %s twice", f.Path)
		}
		listed[f.Path] = f
	}
	root := filepath.Join(dir, PagesDir)
	if st, err := os.Lstat(root); err != nil || !st.IsDir() {
		return nil, loadErr("the slot has no %s/ directory", PagesDir)
	}
	out := fstest.MapFS{}
	var total int64
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		switch {
		case d.IsDir():
			return nil
		case !d.Type().IsRegular():
			return loadErr("%s in the pages isn't a regular file (a link or a device is refused)", rel)
		}
		f, ok := listed[rel]
		if !ok {
			return loadErr("%s is in the pages but not in %s", rel, ManifestFile)
		}
		if total += f.Size; total > maxTotal {
			return loadErr("the pages are over %d bytes", maxTotal)
		}
		b, err := readCapped(p, f.Size)
		if err != nil {
			return loadErr("%s can't be read: %v", rel, err)
		}
		sum := sha256.Sum256(b)
		if int64(len(b)) != f.Size || hex.EncodeToString(sum[:]) != f.SHA256 {
			return loadErr("%s isn't the file %s names (its SHA-256 or size changed)", rel, ManifestFile)
		}
		out[rel] = &fstest.MapFile{Data: b, Mode: 0o444}
		delete(listed, rel)
		return nil
	})
	if err != nil {
		if _, coded := codes.Of(err); coded {
			return nil, err
		}
		return nil, loadErr("the pages can't be read: %v", err)
	}
	for missing := range listed {
		return nil, loadErr("%s is listed in %s but missing", missing, ManifestFile)
	}
	return &Pages{Manifest: m, FS: out}, nil
}

// readCapped reads at most limit bytes of p; a longer file is an error.
func readCapped(p string, limit int64) ([]byte, error) {
	f, err := os.Open(p) // #nosec G304 -- a file in a web slot
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var b bytes.Buffer
	if _, err := b.ReadFrom(io.LimitReader(f, limit+1)); err != nil {
		return nil, err
	}
	if int64(b.Len()) > limit {
		return nil, fmt.Errorf("over %d bytes", limit)
	}
	return b.Bytes(), nil
}

// NeedsBaseOS is what the pages need of the Base OS: the range their
// manifest names, or their own major.minor.
func (m Manifest) NeedsBaseOS(channel string) updatepkg.Range {
	if r, ok := m.Requires[updatepkg.UnitBaseOS]; ok {
		return r
	}
	return updatepkg.DefaultRange(m.Version, channel)
}

// Slots are the web slots under Dir.
type Slots struct{ Dir string }

// Status is what each link names: the version and the slot.
type Status struct {
	Current, Staged, Previous             string
	CurrentSlot, StagedSlot, PreviousSlot string
}

// Status reads the links and the headers in the slots they name.
func (s Slots) Status() Status {
	var st Status
	st.Current, st.CurrentSlot = s.version(linkCurrent)
	st.Staged, st.StagedSlot = s.version(linkStaged)
	st.Previous, st.PreviousSlot = s.version(linkPrevious)
	return st
}

func (s Slots) target(link string) string {
	t, err := os.Readlink(filepath.Join(s.Dir, link))
	if err != nil || (t != slotNames[0] && t != slotNames[1]) {
		return ""
	}
	return filepath.Join(s.Dir, t)
}

func (s Slots) version(link string) (string, string) {
	h, ok := s.Header(link)
	if !ok {
		return "", ""
	}
	return h.Version, filepath.Base(s.target(link))
}

// Header is the verified header in the slot link names, if there's one.
func (s Slots) Header(link string) (updatepkg.Header, bool) {
	dir := s.target(link)
	if dir == "" {
		return updatepkg.Header{}, false
	}
	b, err := os.ReadFile(filepath.Join(dir, HeaderFile)) // #nosec G304 -- a slot of ours
	if err != nil {
		return updatepkg.Header{}, false
	}
	var h updatepkg.Header
	if json.Unmarshal(b, &h) != nil {
		return updatepkg.Header{}, false
	}
	return h, true
}

// CurrentDir is the slot current names, or "" with none.
func (s Slots) CurrentDir() string {
	if _, ok := s.Header(linkCurrent); !ok {
		return ""
	}
	return s.target(linkCurrent)
}

// Stage fills the slot current doesn't name with h's pages: fill unpacks
// the verified, decrypted payload into the directory it's given; the
// result must then load (Load, with key) as the version h names. Only then
// is its header written and staged set. Staging replaces what the slot
// held, a previous or an earlier staged set.
func (s Slots) Stage(h updatepkg.Header, fill func(dir string) error, key *ecdsa.PublicKey) error {
	if updatepkg.UnitOf(h) != updatepkg.UnitBaseWeb {
		return codes.New(codes.UpgradeFormat, "%s %s isn't a Base Web package", h.Name, h.Version)
	}
	if err := os.MkdirAll(s.Dir, 0o755); err != nil { // #nosec G301 -- the osadmin user reads the pages; nothing secret is in them
		return fmt.Errorf("webslots: %w", err)
	}
	slot := s.free()
	for _, l := range []string{linkStaged, linkPrevious} {
		if s.target(l) == filepath.Join(s.Dir, slot) {
			if err := os.Remove(filepath.Join(s.Dir, l)); err != nil {
				return fmt.Errorf("webslots: %w", err)
			}
		}
	}
	dir := filepath.Join(s.Dir, slot)
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("webslots: %w", err)
	}
	if err := os.Mkdir(dir, 0o755); err != nil { // #nosec G301 -- as above
		return fmt.Errorf("webslots: %w", err)
	}
	err := fill(dir)
	var p *Pages
	if err == nil {
		p, err = Load(dir, key)
	}
	if err == nil && p.Manifest.Version != h.Version {
		err = loadErr("the pages are version %s; the signed header says %s", p.Manifest.Version, h.Version)
	}
	if err == nil {
		err = writeHeader(dir, h)
	}
	if err == nil {
		err = s.link(linkStaged, slot)
	}
	if err != nil {
		_ = os.RemoveAll(dir)
		return err
	}
	return nil
}

func writeHeader(dir string, h updatepkg.Header) error {
	b, err := h.Marshal()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, HeaderFile), b, 0o644); err != nil { // #nosec G306 -- the public header
		return fmt.Errorf("webslots: %w", err)
	}
	return nil
}

func (s Slots) free() string {
	if filepath.Base(s.target(linkCurrent)) == slotNames[0] {
		return slotNames[1]
	}
	return slotNames[0]
}

func (s Slots) link(name, slot string) error {
	tmp := filepath.Join(s.Dir, "."+name+".new")
	_ = os.Remove(tmp)
	if err := os.Symlink(slot, tmp); err != nil {
		return fmt.Errorf("webslots: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(s.Dir, name)); err != nil {
		return fmt.Errorf("webslots: %w", err)
	}
	return nil
}

func (s Slots) unlink(name string) error {
	if err := os.Remove(filepath.Join(s.Dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("webslots: %w", err)
	}
	return nil
}

// links is the three links' targets, to put back.
type links map[string]string

func (s Slots) save() links {
	out := links{}
	for _, l := range []string{linkCurrent, linkStaged, linkPrevious} {
		if t := s.target(l); t != "" {
			out[l] = filepath.Base(t)
		}
	}
	return out
}

func (s Slots) restore(l links) error {
	for _, name := range []string{linkCurrent, linkStaged, linkPrevious} {
		var err error
		if t, ok := l[name]; ok {
			err = s.link(name, t)
		} else {
			err = s.unlink(name)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// Apply moves current to the staged slot; the old current, if any,
// becomes previous. It returns the version now current and a func that
// puts the links back, for an apply whose pages don't load.
func (s Slots) Apply() (string, func() error, error) {
	h, ok := s.Header(linkStaged)
	if !ok {
		return "", nil, codes.New(codes.UpgradeNotStaged, "no Base Web is staged; upload or fetch one and stage it first")
	}
	saved := s.save()
	staged, old := filepath.Base(s.target(linkStaged)), s.target(linkCurrent)
	if _, cur := s.Header(linkCurrent); old != "" && cur {
		if err := s.link(linkPrevious, filepath.Base(old)); err != nil {
			return "", nil, err
		}
	}
	if err := s.link(linkCurrent, staged); err != nil {
		return "", nil, err
	}
	if err := s.unlink(linkStaged); err != nil {
		return "", nil, err
	}
	return h.Version, func() error { return s.restore(saved) }, nil
}

// Revert moves current back to the previous slot, which then names the
// slot reverted from; with no previous slot, current goes and the box
// serves its built-in pages. It returns the version now current ("" for
// the built-in pages) and a func that puts the links back.
func (s Slots) Revert() (string, func() error, error) {
	_, hasCur := s.Header(linkCurrent)
	prev, hasPrev := s.Header(linkPrevious)
	if !hasCur {
		return "", nil, codes.New(codes.UpgradeNoPrevious, "the box serves its built-in pages; there's no Base Web to revert")
	}
	saved := s.save()
	if err := s.unlink(linkStaged); err != nil {
		return "", nil, err
	}
	if !hasPrev {
		if err := s.unlink(linkCurrent); err != nil {
			return "", nil, err
		}
		return "", func() error { return s.restore(saved) }, nil
	}
	p, c := filepath.Base(s.target(linkPrevious)), filepath.Base(s.target(linkCurrent))
	if err := s.link(linkCurrent, p); err != nil {
		return "", nil, err
	}
	if err := s.link(linkPrevious, c); err != nil {
		return "", nil, err
	}
	return prev.Version, func() error { return s.restore(saved) }, nil
}

// Unstage drops the staged set: the link and its slot's files. With
// nothing staged it's UPGRADE_NOT_STAGED.
func (s Slots) Unstage() (string, error) {
	h, ok := s.Header(linkStaged)
	dir := s.target(linkStaged)
	if !ok || dir == "" {
		return "", codes.New(codes.UpgradeNotStaged, "no Base Web is staged")
	}
	if err := s.unlink(linkStaged); err != nil {
		return "", err
	}
	if dir == s.target(linkCurrent) || dir == s.target(linkPrevious) {
		return h.Version, nil
	}
	if err := os.RemoveAll(dir); err != nil {
		return h.Version, fmt.Errorf("webslots: %w", err)
	}
	return h.Version, nil
}

// Newer reports whether v is newer than than; an empty than is older than
// everything.
func Newer(v, than string) bool {
	return than == "" || semver.Compare("v"+v, "v"+than) > 0
}
