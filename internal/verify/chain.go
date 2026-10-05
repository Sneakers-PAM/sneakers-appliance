// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"errors"
	"fmt"
	"time"

	log "github.com/Bugs5382/go-log"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/oci"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
)

// Options tune one run of the chain.
type Options struct {
	// Arch is the architecture to verify: amd64 (the default) or arm64.
	Arch string
	// KitVersion is the version compared with the manifest's kitMin.
	KitVersion string
	// Logger receives one line per step; nil discards.
	Logger log.Logger
}

// State is what the steps have established so far. Each step reads what the
// earlier ones set and adds its own.
type State struct {
	Source   Source
	Pins     release.Pins
	Opts     Options
	Digest   digest.Digest
	Layout   *oci.Layout
	Index    ocispec.Index
	Platform ocispec.Descriptor
	OCI      ocispec.Manifest
	// Files maps each layer's title to its descriptor.
	Files    map[string]ocispec.Descriptor
	Manifest *Manifest
	Release  []byte
}

// Step is one link of the chain.
type Step struct {
	Name string
	Run  func(ctx context.Context, s *State) error
}

// Steps is the chain in order. The first failure stops it.
var Steps = []Step{
	{"resolve", stepResolve},
	{"artifact signature", stepArtifactSignature},
	{"appliance manifest", stepManifest},
	{"release manifest", stepRelease},
	{"file digests", stepDigests},
}

// Chain verifies the artifact src points at against the pinned keys and
// returns its manifest for opts.Arch. Nothing is written.
func Chain(ctx context.Context, src Source, pins release.Pins, opts Options) (*Manifest, error) {
	s, err := Run(ctx, src, pins, opts)
	if err != nil {
		return nil, err
	}
	return s.Manifest, nil
}

// Run is Chain returning the whole state, for callers that go on to read
// the verified layout.
func Run(ctx context.Context, src Source, pins release.Pins, opts Options) (*State, error) {
	if opts.Arch == "" {
		opts.Arch = "amd64"
	}
	if opts.Logger == nil {
		opts.Logger = log.Nop()
	}
	s := &State{Source: src, Pins: pins, Opts: opts}
	lg := opts.Logger
	lg.Info("verify: start", log.F("source", src.String()), log.F("arch", opts.Arch), log.F("channel", pins.Channel))
	for _, st := range Steps {
		start := time.Now()
		err := st.Run(ctx, s)
		fields := []log.Field{log.F("step", st.Name), log.F("duration_ms", time.Since(start).Milliseconds())}
		if err != nil {
			code, _ := codes.Of(err)
			lg.Error(err, "verify: refused", append(fields, log.F("code", codes.Symbol(code)))...)
			return nil, err
		}
		lg.Info("verify: step passed", fields...)
	}
	lg.Info("verify: passed", log.F("digest", s.Digest.String()), log.F("version", s.Manifest.Metadata.Version))
	return s, nil
}

// Step 1: resolve the reference to one digest and read the index and the
// architecture's manifest, each checked against its descriptor.
func stepResolve(ctx context.Context, s *State) error {
	d, err := s.Source.Resolve(ctx)
	if err != nil {
		return err
	}
	s.Digest = d
	s.Opts.Logger.Info("verify: resolved", log.F("digest", d.String()))
	if s.Layout, err = s.Source.Open(ctx, d); err != nil {
		return err
	}
	desc, err := descriptorFor(s.Layout, d)
	if err != nil {
		return err
	}
	if s.Index, err = s.Layout.ReadImageIndex(desc); err != nil {
		return digestOrUnreadable(err)
	}
	for _, m := range s.Index.Manifests {
		if m.Platform != nil && m.Platform.OS == "linux" && m.Platform.Architecture == s.Opts.Arch {
			s.Platform = m
			break
		}
	}
	if s.Platform.Digest == "" {
		return codes.New(codes.KitSourceUnreadable, "the artifact has no linux/%s manifest", s.Opts.Arch)
	}
	if s.OCI, err = s.Layout.ReadManifest(s.Platform); err != nil {
		return digestOrUnreadable(err)
	}
	if s.OCI.ArtifactType != ArtifactType {
		return codes.New(codes.KitSourceUnreadable, "the linux/%s manifest is a %q, not a sneakers-os artifact", s.Opts.Arch, s.OCI.ArtifactType)
	}
	s.Files = map[string]ocispec.Descriptor{}
	for _, l := range s.OCI.Layers {
		title := l.Annotations[TitleAnnotation]
		if title == "" {
			return codes.New(codes.KitManifestInvalid, "layer %s has no title", l.Digest)
		}
		if _, dup := s.Files[title]; dup {
			return codes.New(codes.KitManifestInvalid, "two layers are named %s", title)
		}
		s.Files[title] = l
	}
	return nil
}

func digestOrUnreadable(err error) error {
	if errors.Is(err, oci.ErrDigest) {
		return codes.Wrap(codes.KitDigestMismatch, err)
	}
	return codes.Wrap(codes.KitSourceUnreadable, err)
}

// Step 3: parse appliance.yaml and check it against the pins.
func stepManifest(_ context.Context, s *State) error {
	desc, ok := s.Files[FileAppliance]
	if !ok {
		return codes.New(codes.KitManifestInvalid, "the artifact carries no %s", FileAppliance)
	}
	b, err := s.Layout.ReadBlob(desc)
	if err != nil {
		return digestOrUnreadable(err)
	}
	m, err := ParseManifest(b)
	if err != nil {
		return err
	}
	if m.Spec.Arch != s.Opts.Arch {
		return codes.New(codes.KitManifestInvalid, "the linux/%s manifest carries an appliance.yaml for %s", s.Opts.Arch, m.Spec.Arch)
	}
	if err := m.CheckAgainst(s.Pins, s.Opts.KitVersion); err != nil {
		return err
	}
	s.Manifest = m
	return nil
}

// Step 5: every file's SHA-256 against appliance.yaml, and the set of files
// exactly as appliance.yaml lists it.
func stepDigests(_ context.Context, s *State) error {
	want := s.Manifest.ExpectedFiles()
	for title := range s.Files {
		if _, ok := want[title]; !ok && title != FileAppliance {
			return codes.New(codes.KitDigestMismatch, "the artifact carries %s, which appliance.yaml doesn't list", title)
		}
	}
	for title, sum := range want {
		desc, ok := s.Files[title]
		if !ok {
			return codes.New(codes.KitDigestMismatch, "appliance.yaml lists %s, which the artifact doesn't carry", title)
		}
		got, err := s.Layout.HashBlob(desc)
		if err != nil {
			return digestOrUnreadable(fmt.Errorf("%s: %w", title, err))
		}
		if sum != "" && got != sum {
			return codes.New(codes.KitDigestMismatch, "%s has SHA-256 %s; appliance.yaml says %s", title, got, sum)
		}
	}
	return nil
}
