// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package product keeps the product bundle's slots on the state volume:
// two slot directories, a and b, and the links current, staged and
// previous between them. The product (k0s, its images and stacks) runs
// from current. A bundle is staged into the slot current doesn't name,
// applied by moving current to it (the old current becomes previous), and
// reverted by moving current back to previous, so the previous slot is the
// only way back, as with the base image's slots. The first install is a
// stage and an apply with no previous slot.
package product

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/mod/semver"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productinfo"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

// Dir is the slots' directory on the box.
const Dir = productinfo.Dir

// BundleFile is the verified header, written into a slot once its bundle
// checks out; a slot without it is never used.
const BundleFile = productinfo.BundleFile

// The links in Dir.
const (
	linkCurrent  = "current"
	linkStaged   = "staged"
	linkPrevious = "previous"
)

var slotNames = []string{"a", "b"}

// Slots are the product slots under Dir.
type Slots struct{ Dir string }

// Status is the version each link names; empty when it names none.
type Status struct {
	Installed, Staged, Previous string
}

// Current is the current slot's path; the product runs from it.
func (s Slots) Current() string { return s.target(linkCurrent) }

// Status reads the links and the headers in the slots they name.
func (s Slots) Status() Status {
	return Status{Installed: s.version(linkCurrent), Staged: s.version(linkStaged), Previous: s.version(linkPrevious)}
}

func (s Slots) target(link string) string {
	t, err := os.Readlink(filepath.Join(s.Dir, link))
	if err != nil {
		return ""
	}
	return filepath.Join(s.Dir, t)
}

func (s Slots) version(link string) string {
	h, _ := s.header(link)
	return h.Version
}

func (s Slots) header(link string) (updatepkg.Header, bool) {
	dir := s.target(link)
	if dir == "" {
		return updatepkg.Header{}, false
	}
	b, err := os.ReadFile(filepath.Join(dir, BundleFile)) // #nosec G304 -- a slot of ours
	if err != nil {
		return updatepkg.Header{}, false
	}
	var h updatepkg.Header
	if json.Unmarshal(b, &h) != nil {
		return updatepkg.Header{}, false
	}
	return h, true
}

// Installed is the installed bundle's verified header, if there is one.
func (s Slots) Installed() (updatepkg.Header, bool) { return s.header(linkCurrent) }

// Unstage drops the staged bundle: the staged link and its slot's files.
// The installed and previous slots are untouched. With nothing staged
// it's UPGRADE_NOT_STAGED. It returns the version dropped.
func (s Slots) Unstage() (string, error) {
	v, dir := s.version(linkStaged), s.target(linkStaged)
	if v == "" || dir == "" {
		return "", codes.New(codes.UpgradeNotStaged, "no product bundle is staged")
	}
	if err := s.unlink(linkStaged); err != nil {
		return "", err
	}
	if dir == s.target(linkCurrent) || dir == s.target(linkPrevious) {
		return v, nil
	}
	if err := os.RemoveAll(dir); err != nil {
		return v, fmt.Errorf("product: %w", err)
	}
	return v, nil
}

// Stage fills the slot current doesn't name with h's bundle: fill unpacks
// the verified, decrypted payload into the directory it's given. Only a
// version newer than the installed one stages (UPGRADE_DOWNGRADE). The
// unpacked bundle must then check out against its release.yaml and key
// (bundle.CheckProduct); only then is its header written and staged set.
// Staging replaces what that slot held, a previous or an earlier staged
// bundle.
func (s Slots) Stage(h updatepkg.Header, fill func(dir string) error, key *ecdsa.PublicKey) error {
	if !h.IsProduct() {
		return codes.New(codes.UpgradeFormat, "%s %s isn't a product bundle", h.Name, h.Version)
	}
	if cur := s.version(linkCurrent); cur != "" && semver.Compare("v"+h.Version, "v"+cur) <= 0 {
		return codes.New(codes.UpgradeDowngrade, "the product bundle %s isn't newer than the installed %s", h.Version, cur)
	}
	if err := os.MkdirAll(s.Dir, 0o755); err != nil { // #nosec G301 -- k0s reads the slots as root; nothing secret is in them
		return fmt.Errorf("product: %w", err)
	}
	slot := s.free()
	for _, l := range []string{linkStaged, linkPrevious} {
		if s.target(l) == filepath.Join(s.Dir, slot) {
			if err := os.Remove(filepath.Join(s.Dir, l)); err != nil {
				return fmt.Errorf("product: %w", err)
			}
		}
	}
	dir := filepath.Join(s.Dir, slot)
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("product: %w", err)
	}
	if err := os.Mkdir(dir, 0o755); err != nil { // #nosec G301 -- as above
		return fmt.Errorf("product: %w", err)
	}
	err := fill(dir)
	if err == nil {
		err = Finish(dir, h.Arch, key)
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

// Finish checks an unpacked product bundle in dir, makes its k0s and
// helm executable (the payload's files are all 0644) and renders the RBAC
// for the values its product.yaml exposes (productspec.WriteRBAC).
func Finish(dir, arch string, key *ecdsa.PublicKey) error {
	if _, err := bundle.CheckProduct(os.DirFS(dir), arch, key); err != nil {
		return err
	}
	if err := productspec.WriteRBAC(dir); err != nil {
		return err
	}
	for _, bin := range []string{bundle.ProductK0s, bundle.ProductHelm} {
		err := os.Chmod(filepath.Join(dir, bin), 0o755) // #nosec G302 -- a checked binary
		if bin == bundle.ProductHelm && errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("product: %w", err)
		}
	}
	return nil
}

func writeHeader(dir string, h updatepkg.Header) error {
	b, err := h.Marshal()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, BundleFile), b, 0o644); err != nil { // #nosec G306 -- the public header
		return fmt.Errorf("product: %w", err)
	}
	return nil
}

// free is the slot current doesn't name.
func (s Slots) free() string {
	cur := filepath.Base(s.target(linkCurrent))
	if cur == slotNames[0] {
		return slotNames[1]
	}
	return slotNames[0]
}

// link points name at slot, replacing it in one rename.
func (s Slots) link(name, slot string) error {
	tmp := filepath.Join(s.Dir, "."+name+".new")
	_ = os.Remove(tmp)
	if err := os.Symlink(slot, tmp); err != nil {
		return fmt.Errorf("product: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(s.Dir, name)); err != nil {
		return fmt.Errorf("product: %w", err)
	}
	return nil
}

func (s Slots) unlink(name string) error {
	if err := os.Remove(filepath.Join(s.Dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("product: %w", err)
	}
	return nil
}

// Apply moves current to the staged slot, and the old current, if any,
// becomes previous. It returns the version now installed.
func (s Slots) Apply() (string, error) {
	v := s.version(linkStaged)
	if v == "" {
		return "", codes.New(codes.UpgradeNotStaged, "no product bundle is staged; upload or fetch one and stage it first")
	}
	staged, old := filepath.Base(s.target(linkStaged)), s.target(linkCurrent)
	if old != "" && s.version(linkCurrent) != "" {
		if err := s.link(linkPrevious, filepath.Base(old)); err != nil {
			return "", err
		}
	}
	if err := s.link(linkCurrent, staged); err != nil {
		return "", err
	}
	return v, s.unlink(linkStaged)
}

// Revert moves current back to the previous slot, which then names the
// slot reverted from. It returns the version now installed.
func (s Slots) Revert() (string, error) {
	v := s.version(linkPrevious)
	if v == "" {
		return "", codes.New(codes.UpgradeNoPrevious, "there's no previous product bundle to go back to")
	}
	prev, cur := filepath.Base(s.target(linkPrevious)), filepath.Base(s.target(linkCurrent))
	if err := s.unlink(linkStaged); err != nil {
		return "", err
	}
	if err := s.link(linkCurrent, prev); err != nil {
		return "", err
	}
	return v, s.link(linkPrevious, cur)
}
