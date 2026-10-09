// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package basepatch rebuilds a Base OS release from the release a box runs
// and a patch (spec 5, Section 2.10). A patch's payload is the target's
// signed OCI layout without its two large blobs, the root image and the
// UKI, plus a `zstd --patch-from` delta of each against the base's:
//
//	oci-layout, index.json, blobs/sha256/...   the target layout, less two blobs
//	patch/root.delta                           base root image -> target root image
//	patch/uki.delta                            base UKI        -> target UKI
//
// The box checks the base first (the running root image and UKI by
// SHA-256), rebuilds both blobs, checks each against the SHA-256 the signed
// header names (which is also the blob's digest, pinned by the signed
// artifact), and only then hands the layout to the usual Stage, which runs
// the whole verify chain on it. The result is byte for byte the layout the
// full .bin unpacks.
package basepatch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

// The deltas' paths in a patch payload.
const (
	Dir       = "patch"
	RootDelta = Dir + "/root.delta"
	UKIDelta  = Dir + "/uki.delta"
)

// MaxWindow bounds the delta's window: the encoder's long mode (zstd
// --long=30) fits a root image of up to 1 GiB.
const MaxWindow = 1 << 30

// Spec is what the box checks and rebuilds, from a patch's signed header.
type Spec struct {
	BaseVersion    string
	BaseRootSHA256 string
	BaseRootSize   int64
	BaseUKISHA256  string
	RootSHA256     string
	UKISHA256      string
}

// SpecOf is the spec a verified patch header names. A patch without its
// hashes can't be rebuilt (UPGRADE_FORMAT).
func SpecOf(h updatepkg.Header) (Spec, error) {
	if err := h.Applicable(); err != nil {
		return Spec{}, err
	}
	return Spec{BaseVersion: h.Base.Version, BaseRootSHA256: h.Base.RootSHA256, BaseRootSize: h.Base.RootSize, BaseUKISHA256: h.Base.UKISHA256,
		RootSHA256: h.Target.RootSHA256, UKISHA256: h.Target.UKISHA256}, nil
}

// ReadBase reads the base root image (the first size bytes of the running
// slot) and checks it and the running UKI against s. A wrong base is
// UPGRADE_PATCH_BASE, before anything is written.
func ReadBase(s Spec, running string, slot io.ReaderAt, uki []byte) ([]byte, error) {
	if running != s.BaseVersion {
		return nil, codes.New(codes.UpgradePatchBase, "the patch is for %s; this box runs %s", s.BaseVersion, running)
	}
	if s.BaseRootSize <= 0 || s.BaseRootSize > MaxWindow {
		return nil, codes.New(codes.UpgradePatchBase, "the patch's base root image is %d bytes, which this box can't rebuild from", s.BaseRootSize)
	}
	if got := sum(uki); got != s.BaseUKISHA256 {
		return nil, codes.New(codes.UpgradePatchBase, "the running UKI isn't the one the patch was made from (SHA-256 %s, the patch's base has %s)", short(got), short(s.BaseUKISHA256))
	}
	root := make([]byte, s.BaseRootSize)
	if _, err := slot.ReadAt(root, 0); err != nil {
		return nil, codes.New(codes.UpgradePatchBase, "the running root slot can't be read: %v", err)
	}
	if got := sum(root); got != s.BaseRootSHA256 {
		return nil, codes.New(codes.UpgradePatchBase, "the running root image isn't the one the patch was made from (SHA-256 %s, the patch's base has %s)", short(got), short(s.BaseRootSHA256))
	}
	return root, nil
}

// Rebuild writes the target's root image and UKI into the layout at dir
// from the base's and the deltas in dir, checks each against s
// (UPGRADE_PATCH_RESULT, and nothing is left behind), and removes the
// deltas. dir is then the target's whole layout.
func Rebuild(dir string, s Spec, baseRoot, baseUKI []byte) error {
	for _, f := range []struct {
		delta, want string
		base        []byte
	}{{RootDelta, s.RootSHA256, baseRoot}, {UKIDelta, s.UKISHA256, baseUKI}} {
		if err := rebuildOne(dir, f.delta, f.want, f.base); err != nil {
			return err
		}
	}
	if err := os.RemoveAll(filepath.Join(dir, Dir)); err != nil {
		return fmt.Errorf("basepatch: %w", err)
	}
	return nil
}

func rebuildOne(dir, delta, want string, base []byte) error {
	in, err := os.Open(filepath.Join(dir, delta)) // #nosec G304 -- a path in the patch's own work directory
	if err != nil {
		return codes.New(codes.UpgradePatchResult, "the patch carries no %s", filepath.Base(delta))
	}
	defer func() { _ = in.Close() }()
	blobs := filepath.Join(dir, "blobs", "sha256")
	if err := os.MkdirAll(blobs, 0o755); err != nil { // #nosec G301 -- a layout's blobs are public
		return fmt.Errorf("basepatch: %w", err)
	}
	dst := filepath.Join(blobs, want)
	tmp := dst + ".rebuild"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644) // #nosec G302 G304 -- a layout's blobs are public
	if err != nil {
		return fmt.Errorf("basepatch: %w", err)
	}
	h := sha256.New()
	err = Apply(in, base, io.MultiWriter(out, h))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && hex.EncodeToString(h.Sum(nil)) != want {
		err = codes.New(codes.UpgradePatchResult, "%s rebuilds to SHA-256 %s, not the %s the signed header names", filepath.Base(delta), short(hex.EncodeToString(h.Sum(nil))), short(want))
	}
	if err != nil {
		_ = os.Remove(tmp)
		if _, coded := codes.Of(err); coded {
			return err
		}
		return codes.New(codes.UpgradePatchResult, "%s doesn't rebuild: %v", filepath.Base(delta), err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return fmt.Errorf("basepatch: %w", err)
	}
	return nil
}

// Apply writes the file delta rebuilds from base to w: delta is a zstd
// frame made with `zstd --patch-from=<base>`.
func Apply(delta io.Reader, base []byte, w io.Writer) error {
	dec, err := zstd.NewReader(delta, zstd.WithDecoderDictRaw(0, base), zstd.WithDecoderMaxWindow(MaxWindow), zstd.WithDecoderMaxMemory(4<<30), zstd.WithDecoderConcurrency(1))
	if err != nil {
		return err
	}
	defer dec.Close()
	if _, err := io.Copy(w, dec); err != nil {
		return err
	}
	return nil
}

// MakeDelta writes a delta of target against base that Apply rebuilds.
// The release build makes its deltas with `zstd --patch-from` (long mode,
// level 19), which Apply reads the same way; this is the same format from
// Go, for tests and small files.
func MakeDelta(base, target []byte, w io.Writer) error {
	enc, err := zstd.NewWriter(w, zstd.WithEncoderDictRaw(0, base), zstd.WithEncoderLevel(zstd.SpeedBestCompression), zstd.WithEncoderConcurrency(1))
	if err != nil {
		return err
	}
	if _, err := enc.Write(target); err != nil {
		_ = enc.Close()
		return err
	}
	return enc.Close()
}

// Check rebuilds target from base and delta in memory and compares it with
// target: the build's apply check, run with the box's own code.
func Check(delta io.Reader, base, target []byte) error {
	var got bytes.Buffer
	if err := Apply(delta, base, &got); err != nil {
		return err
	}
	if !bytes.Equal(got.Bytes(), target) {
		return errors.New("basepatch: the delta doesn't rebuild the target exactly")
	}
	return nil
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
