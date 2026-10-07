// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package imageupgrade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"

	log "github.com/Bugs5382/go-log"
	"golang.org/x/mod/semver"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/bootcmd"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/ukipcr"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verify"
)

// ESP is the mounted EFI System Partition. WriteFile must be durable
// (written, synced, renamed into place) before it returns: an upgrade cut
// off by the reboot it triggers mustn't leave a half-written entry the
// firmware would try.
type ESP interface {
	List(dir string) ([]string, error)
	WriteFile(rel string, r io.Reader) error
	Rename(from, to string) error
	Remove(rel string) error
}

// Slots are the two root partitions.
type Slots interface {
	// WriteInactive writes the root image to the slot the box isn't
	// running from and sets that slot's PARTUUID.
	WriteInactive(ctx context.Context, r io.Reader, size int64, partUUID string) error
}

// Sealer adds and prunes the state key's sealed copies, one per bootable
// UKI. In key-file mode both are no-ops.
type Sealer interface {
	// SealForImage adds a copy the UKI with SHA-256 ukiSHA will unseal,
	// given the PCR 11 value its stub will measure.
	SealForImage(ctx context.Context, ukiSHA string, pcr11 []byte) error
	// Prune drops every copy whose UKI isn't in keep.
	Prune(ctx context.Context, keep []string) error
}

// Stager runs the Image service's work.
type Stager struct {
	ESP    ESP
	Slots  Slots
	Sealer Sealer
	Pins   release.Pins
	// Running is the version the box booted (sneakers.version).
	Running string
	// InitVersion is checked against a release's kitMin; empty means the
	// version stamped into this build.
	InitVersion string
	// WorkDir holds the fetched copy of a release while it's staged.
	WorkDir string
	Logger  log.Logger
}

// Stage verifies a release against the pins compiled into the running
// init (the whole chain of spec 1 Section 2.3), refuses a downgrade, writes
// its root into the inactive slot, adds a sealed copy of the state key for
// its UKI, and only then adds its ESP entry with three boot tries. Every
// release but the running one and the new one is removed, so the box holds
// at most two. Nothing is written before verification completes.
func (s *Stager) Stage(ctx context.Context, src verify.Source, arch string) (string, error) {
	lg := s.logger()
	d, err := src.Resolve(ctx)
	if err != nil {
		return "", err
	}
	l, err := src.Fetch(ctx, d, path.Join(s.WorkDir, d.Encoded()))
	if err != nil {
		return "", err
	}
	iv := s.InitVersion
	if iv == "" {
		iv = release.Version
	}
	st, err := verify.Run(ctx, verify.Pinned(l, d), s.Pins, verify.Options{Arch: arch, KitVersion: iv, Logger: lg})
	if err != nil {
		return "", err
	}
	m := st.Manifest
	ver := m.Metadata.Version
	if semver.Compare("v"+ver, "v"+s.Running) <= 0 {
		return "", codes.New(codes.UpgradeDowngrade, "%s isn't newer than the running %s", ver, s.Running)
	}
	uki, err := readAll(st, m.Spec.Boot.UKI.File)
	if err != nil {
		return "", err
	}
	pred, err := ukipcr.Predict(uki)
	if err != nil {
		return "", codes.Wrap(codes.UpgradeUnpredictable, err)
	}
	guid, err := bootcmd.SlotGUID(m.Spec.Root.Verity.RootHash)
	if err != nil {
		return "", codes.Wrap(codes.KitManifestInvalid, err)
	}
	root, err := st.Layout.OpenBlob(st.Files[m.Spec.Root.File])
	if err != nil {
		return "", err
	}
	err = s.Slots.WriteInactive(ctx, root, st.Files[m.Spec.Root.File].Size, guid)
	_ = root.Close()
	if err != nil {
		return "", fmt.Errorf("imageupgrade: write the inactive slot: %w", err)
	}
	sum := sha256.Sum256(uki)
	if err := s.Sealer.SealForImage(ctx, hex.EncodeToString(sum[:]), pred.Value); err != nil {
		return "", fmt.Errorf("imageupgrade: seal the state key for %s: %w", ver, err)
	}
	entries, err := s.entries()
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.Version != s.Running {
			lg.Info("imageupgrade: removing an older entry", log.F("entry", e.Name))
			if err := s.ESP.Remove(path.Join(UKIDir, e.Name)); err != nil {
				return "", err
			}
		}
	}
	if err := s.ESP.WriteFile(path.Join(UKIDir, EntryName(ver, Tries, 0)), bytes.NewReader(uki)); err != nil {
		return "", fmt.Errorf("imageupgrade: write the ESP entry: %w", err)
	}
	lg.Info("imageupgrade: staged", log.F("version", ver), log.F("tries", Tries))
	return ver, nil
}

// MarkGood makes the running release's entry known good (no counter) and
// prunes sealed copies for UKIs no longer on the ESP.
func (s *Stager) MarkGood(ctx context.Context, keep []string) error {
	entries, err := s.entries()
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Version == s.Running && e.Counted {
			if err := s.ESP.Rename(path.Join(UKIDir, e.Name), path.Join(UKIDir, GoodName(e.Version))); err != nil {
				return err
			}
			s.logger().Info("imageupgrade: marked good", log.F("version", e.Version))
		}
	}
	return s.Sealer.Prune(ctx, keep)
}

// Rollback marks the running release bad so systemd-boot boots the
// previous one next. With no previous release it's UPGRADE_NO_PREVIOUS.
func (s *Stager) Rollback() error {
	entries, err := s.entries()
	if err != nil {
		return err
	}
	var running *Entry
	previous := false
	for i, e := range entries {
		switch {
		case e.Version == s.Running:
			running = &entries[i]
		case !e.Bad():
			previous = true
		}
	}
	if running == nil || !previous {
		return codes.New(codes.UpgradeNoPrevious, "there's no previous release to roll back to")
	}
	return s.ESP.Rename(path.Join(UKIDir, running.Name), path.Join(UKIDir, EntryName(running.Version, 0, running.Done+1)))
}

// Status is what the Image service reports.
type Status struct {
	Running string
	Staged  string
	// Failed is a newer release that used up its tries: boot counting
	// fell back from it.
	Failed string
}

// Status reads the entries.
func (s *Stager) Status() (Status, error) {
	entries, err := s.entries()
	if err != nil {
		return Status{}, err
	}
	st := Status{Running: s.Running}
	for _, e := range entries {
		if e.Version == s.Running {
			continue
		}
		newer := semver.Compare("v"+e.Version, "v"+s.Running) > 0
		switch {
		case newer && e.Bad():
			st.Failed = e.Version
		case newer && e.Counted:
			st.Staged = e.Version
		}
	}
	return st, nil
}

func (s *Stager) entries() ([]Entry, error) {
	names, err := s.ESP.List(UKIDir)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, n := range names {
		if e, ok := ParseEntry(n); ok {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Stager) logger() log.Logger {
	if s.Logger == nil {
		return log.Nop()
	}
	return s.Logger
}

func readAll(st *verify.State, title string) ([]byte, error) {
	f, err := st.Layout.OpenBlob(st.Files[title])
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 512<<20))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != st.Files[title].Size {
		return nil, errors.New("imageupgrade: the UKI is larger than 512 MiB")
	}
	return b, nil
}
