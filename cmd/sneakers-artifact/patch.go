// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/basepatch"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/oci"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

// patchSpecFile is what patch-make leaves for bin-pack --patch-spec.
const patchSpecFile = "patch-spec.json"

// patchSpec is a patch's base and target as patch-make found them.
type patchSpec struct {
	Method string                `json:"method"`
	Base   updatepkg.PatchBase   `json:"base"`
	Target updatepkg.PatchTarget `json:"target"`
}

// layoutVersion is the release version an artifact layout names (its
// image index's ref name).
func layoutVersion(dir string) (string, error) {
	l, err := oci.Open(dir)
	if err != nil {
		return "", err
	}
	idx, err := l.Index()
	if err != nil {
		return "", err
	}
	for _, d := range idx.Manifests {
		if v := d.Annotations[ocispec.AnnotationRefName]; d.MediaType == ocispec.MediaTypeImageIndex && v != "" {
			return v, nil
		}
	}
	return "", fmt.Errorf("%s names no release version", dir)
}

// zstdDelta makes a delta with the zstd command: long mode, level 19, the
// base as the reference.
func zstdDelta(bin string) basepatch.DeltaFunc {
	return func(base, target, delta string) error {
		cmd := exec.Command(bin, "-q", "-f", "-19", "--long=30", "--patch-from="+base, target, "-o", delta) // #nosec G204 -- the build's own zstd and files
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %w: %s", bin, err, out)
		}
		return nil
	}
}

// patchMakeCmd writes a Base OS patch's payload from a base and a target
// artifact, checks that each delta rebuilds exactly with the box's own
// decoder, and leaves the spec bin-pack --patch-spec puts in the header.
func patchMakeCmd() *cobra.Command {
	var base, target, out, zstdBin string
	cmd := &cobra.Command{
		Use:   "patch-make",
		Short: "Write a Base OS patch's payload (the target layout less its root image and UKI, plus their zstd deltas) and its spec",
		RunE: func(cmd *cobra.Command, _ []string) error {
			bv, err := layoutVersion(base)
			if err != nil {
				return err
			}
			tv, err := layoutVersion(target)
			if err != nil {
				return err
			}
			payload := filepath.Join(out, "payload")
			if err := os.MkdirAll(payload, 0o755); err != nil { // #nosec G301 -- release outputs are public
				return err
			}
			pb, pt, err := basepatch.MakePayload(base, target, payload, zstdDelta(zstdBin))
			if err != nil {
				return err
			}
			pb.Version, pt.Version = bv, tv
			b, err := json.MarshalIndent(patchSpec{Method: updatepkg.MethodZstdPatch, Base: pb, Target: pt}, "", "  ")
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(out, patchSpecFile), append(b, '\n'), 0o644); err != nil { // #nosec G306 -- public
				return err
			}
			var size int64
			for _, d := range []string{basepatch.RootDelta, basepatch.UKIDelta} {
				if fi, err := os.Stat(filepath.Join(payload, d)); err == nil {
					size += fi.Size()
				}
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "patch %s from %s: deltas %d bytes, checked\n", tv, bv, size)
			return err
		},
	}
	f := cmd.Flags()
	f.StringVar(&base, "base", "", "the base release's signed artifact layout")
	f.StringVar(&target, "target", "", "the target release's signed artifact layout")
	f.StringVar(&out, "out", "", "the work directory: payload/ and "+patchSpecFile)
	f.StringVar(&zstdBin, "zstd", "zstd", "the zstd command")
	for _, r := range []string{"base", "target", "out"} {
		_ = cmd.MarkFlagRequired(r)
	}
	return cmd
}

// readPatchSpec fills h as a patch from the spec patch-make wrote; the
// full release it falls back to is h's Base OS full file, by its earlier
// name when previous is set (a lab patch for boxes before the
// version-only names, which refuse the new name).
func readPatchSpec(p string, h *updatepkg.Header, previous bool) error {
	b, err := os.ReadFile(p) // #nosec G304 -- the build's own spec
	if err != nil {
		return err
	}
	var s patchSpec
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("%s: %w", p, err)
	}
	if s.Target.Version != h.Version {
		return fmt.Errorf("%s is a patch to %s; --version is %s", p, s.Target.Version, h.Version)
	}
	h.Kind, h.Bases, h.Method = updatepkg.KindPatch, []string{s.Base.Version}, s.Method
	base, target := s.Base, s.Target
	h.Base, h.Target = &base, &target
	full := *h
	full.Kind, full.Bases, full.Method, full.Base, full.Target = updatepkg.KindFull, nil, "", nil, nil
	h.Target.FullBin = updatepkg.FileName(full)
	if previous {
		h.Target.FullBin = updatepkg.PreviousFileName(full)
	}
	return nil
}

// patchCheckCmd opens a sealed patch the way the box does and rebuilds its
// target from the base artifact: the build's apply check. With --extract
// the rebuilt layout is left there, for sneakers-kit verify.
func patchCheckCmd() *cobra.Command {
	var base, key, channel, identity, identityUKI, extract string
	cmd := &cobra.Command{
		Use:   "patch-check <patch.bin>",
		Short: "Verify and decrypt a Base OS patch and rebuild its release from the base artifact, as the box does",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pub, err := os.ReadFile(key) // #nosec G304 -- a public key file
			if err != nil {
				return err
			}
			f, err := os.Open(args[0])
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			fi, err := f.Stat()
			if err != nil {
				return err
			}
			p, err := updatepkg.Read(f, fi.Size())
			if err != nil {
				return err
			}
			if err := p.Verify(pub, channel); err != nil {
				return err
			}
			spec, err := basepatch.SpecOf(p.Header)
			if err != nil {
				return err
			}
			ident, err := identityOf(identity, identityUKI)
			if err != nil {
				return err
			}
			dir := extract
			if dir == "" {
				if dir, err = os.MkdirTemp("", "patch-check-"); err != nil {
					return err
				}
				defer func() { _ = os.RemoveAll(dir) }()
			}
			pr, pw := io.Pipe()
			done := make(chan error, 1)
			go func() { done <- updatepkg.Untar(pr, dir) }()
			err = p.Decrypt(ident, pw)
			_ = pw.CloseWithError(err)
			if uerr := <-done; err == nil {
				err = uerr
			}
			if err != nil {
				return err
			}
			big, err := basepatch.BlobsOf(base)
			if err != nil {
				return err
			}
			root, err := os.Open(filepath.Join(base, "blobs", "sha256", big.Root.Digest.Encoded())) // #nosec G304 -- a build input
			if err != nil {
				return err
			}
			defer func() { _ = root.Close() }()
			uki, err := os.ReadFile(filepath.Join(base, "blobs", "sha256", big.UKI.Digest.Encoded())) // #nosec G304 -- a build input
			if err != nil {
				return err
			}
			baseRoot, err := basepatch.ReadBase(spec, spec.BaseVersion, root, uki)
			if err != nil {
				return err
			}
			if err := basepatch.Rebuild(dir, spec, baseRoot, uki); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "rebuilt %s from %s: root %s, UKI %s\n", p.Header.Version, spec.BaseVersion, spec.RootSHA256[:12], spec.UKISHA256[:12])
			return err
		},
	}
	f := cmd.Flags()
	f.StringVar(&base, "base", "", "the base release's signed artifact layout")
	f.StringVar(&key, "release-key", "", "the channel's release public key (cosign.pub)")
	f.StringVar(&channel, "channel", "", "production or lab")
	f.StringVar(&identity, "identity", "", "the update key")
	f.StringVar(&identityUKI, "identity-uki", "", "a UKI whose update key decrypts, as the box does")
	f.StringVar(&extract, "extract", "", "leave the rebuilt layout here")
	cmd.MarkFlagsMutuallyExclusive("identity", "identity-uki")
	cmd.MarkFlagsOneRequired("identity", "identity-uki")
	for _, r := range []string{"base", "release-key", "channel"} {
		_ = cmd.MarkFlagRequired(r)
	}
	return cmd
}
