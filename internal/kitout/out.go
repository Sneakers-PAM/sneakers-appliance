// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package kitout runs a kit build: resolve the reference once, fetch that
// digest into a private layout, verify the copy, hand the same copy to the
// format's writer, and move the result into place only when every step
// succeeded. A refused or failed build leaves the output directory as it
// was.
package kitout

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verify"
)

// Options tune a build.
type Options struct {
	Out        string
	Arch       string
	DiskSize   int64
	KitVersion string
	Logger     log.Logger
}

// Writer turns a verified artifact into one output format. It writes only
// into dir.
type Writer interface {
	Format() string
	// Arches lists the architectures the format supports.
	Arches() []string
	Write(ctx context.Context, s *verify.State, opts Options, dir string) error
}

// Writers is the set of formats a kit carries.
type Writers map[string]Writer

// NewWriters indexes ws by format.
func NewWriters(ws ...Writer) Writers {
	out := Writers{}
	for _, w := range ws {
		out[w.Format()] = w
	}
	return out
}

// Formats lists the format names, sorted.
func (ws Writers) Formats() []string {
	var out []string
	for f := range ws {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// Verify runs the whole chain on a private copy of the artifact in a
// temporary directory and removes the copy afterwards.
func Verify(ctx context.Context, src verify.Source, pins release.Pins, opts Options) (*verify.Manifest, error) {
	tmp, err := os.MkdirTemp("", "sneakers-kit-verify-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	s, err := fetchAndVerify(ctx, src, pins, opts, filepath.Join(tmp, "layout"))
	if err != nil {
		return nil, err
	}
	return s.Manifest, nil
}

func fetchAndVerify(ctx context.Context, src verify.Source, pins release.Pins, opts Options, dir string) (*verify.State, error) {
	if opts.Logger == nil {
		opts.Logger = log.Nop()
	}
	lg := opts.Logger
	d, err := src.Resolve(ctx)
	if err != nil {
		return nil, err
	}
	lg.Info("kit: resolved", log.F("source", src.String()), log.F("digest", d.String()))
	start := time.Now()
	l, err := src.Fetch(ctx, d, dir)
	if err != nil {
		return nil, err
	}
	lg.Info("kit: fetched", log.F("digest", d.String()), log.F("duration_ms", time.Since(start).Milliseconds()))
	return verify.Run(ctx, verify.Pinned(l, d), pins, verify.Options{Arch: opts.Arch, KitVersion: opts.KitVersion, Logger: lg})
}

// Run verifies src and builds format into opts.Out. It returns the paths it
// wrote.
func (ws Writers) Run(ctx context.Context, src verify.Source, pins release.Pins, format string, opts Options) ([]string, error) {
	if opts.Logger == nil {
		opts.Logger = log.Nop()
	}
	if opts.Arch == "" {
		opts.Arch = "amd64"
	}
	w, ok := ws[format]
	if !ok {
		return nil, fmt.Errorf("this kit doesn't build %q (it builds %v)", format, ws.Formats())
	}
	if !contains(w.Arches(), opts.Arch) {
		return nil, fmt.Errorf("%s is built for %v, not %s", format, w.Arches(), opts.Arch)
	}
	if err := os.MkdirAll(opts.Out, 0o750); err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp(opts.Out, ".sneakers-kit-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	s, err := fetchAndVerify(ctx, src, pins, opts, filepath.Join(tmp, "layout"))
	if err != nil {
		return nil, err
	}
	work := filepath.Join(tmp, "out")
	if err := os.Mkdir(work, 0o750); err != nil {
		return nil, err
	}
	start := time.Now()
	opts.Logger.Info("kit: writing", log.F("format", format), log.F("arch", opts.Arch))
	if err := w.Write(ctx, s, opts, work); err != nil {
		opts.Logger.Error(err, "kit: write failed", log.F("format", format))
		return nil, err
	}
	entries, err := os.ReadDir(work)
	if err != nil {
		return nil, err
	}
	var written []string
	for _, e := range entries {
		to := filepath.Join(opts.Out, e.Name())
		if _, err := os.Lstat(to); err == nil {
			removeAll(written)
			return nil, fmt.Errorf("%s already exists; move it away or pick another --out", to)
		}
		if err := os.Rename(filepath.Join(work, e.Name()), to); err != nil {
			removeAll(written)
			return nil, err
		}
		written = append(written, to)
	}
	opts.Logger.Info("kit: built", log.F("format", format), log.F("files", len(written)), log.F("duration_ms", time.Since(start).Milliseconds()))
	return written, nil
}

// BaseName is the stem every output of s uses: sneakers-<version>-<arch>,
// with -LAB for a lab release.
func BaseName(s *verify.State) string {
	n := fmt.Sprintf("sneakers-%s-%s", s.Manifest.Metadata.Version, s.Manifest.Spec.Arch)
	if s.Manifest.Metadata.Channel == release.ChannelLab {
		n += "-LAB"
	}
	return n
}

func removeAll(paths []string) {
	for _, p := range paths {
		_ = os.RemoveAll(p)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
