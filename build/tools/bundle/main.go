// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command bundle builds the airgap image bundle from release.yaml (pull) and
// checks a bundle directory against it in both directions (check), for
// build/bundle/build.sh. manifest writes the manifest or index bytes of one
// pinned image, which the release key (or a lab build's lab key) then
// signs, and images lists every image the bundle carries, "<image>
// <digest>" a line, refusing a placeholder digest.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sigbundle"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "bundle:", codes.Describe(err))
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: bundle pull|check|manifest|images [flags]")
	}
	switch args[0] {
	case "manifest":
		return manifest(args[1:])
	case "images":
		return images(args[1:], os.Stdout)
	}
	fl := flag.NewFlagSet("bundle "+args[0], flag.ContinueOnError)
	relPath := fl.String("release", "", "release.yaml")
	keyPath := fl.String("key", "", "the org release key (cosign.pub)")
	arch := fl.String("arch", "amd64", "the architecture to pull")
	sigs := fl.String("signatures", "", "directory of <hex>.sigstore.json org signatures")
	out := fl.String("out", "", "the bundle directory (pull: empty or missing)")
	plain := fl.Bool("plain-http", false, "talk to registries without TLS (a lab registry only)")
	if err := fl.Parse(args[1:]); err != nil {
		return err
	}
	relYAML, err := os.ReadFile(*relPath) // #nosec G304 G703 -- a build tool reading the file it was handed
	if err != nil {
		return err
	}
	rel, err := bundle.ParseRelease(relYAML)
	if err != nil {
		return err
	}
	pem, err := os.ReadFile(*keyPath) // #nosec G304 G703 -- as above
	if err != nil {
		return err
	}
	key, err := sigbundle.ParsePublicKey(pem)
	if err != nil {
		return err
	}
	switch args[0] {
	case "check":
		return bundle.CheckImages(os.DirFS(*out), ".", rel, key)
	case "pull":
		epoch := time.Unix(0, 0)
		if s := os.Getenv("SOURCE_DATE_EPOCH"); s != "" {
			n, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				return fmt.Errorf("SOURCE_DATE_EPOCH %q isn't a number", s)
			}
			epoch = time.Unix(n, 0)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		lg := log.NewLoggerWithOptions("bundle", log.WithOutput(os.Stderr), log.WithDefaultFormat(log.FormatConsole), log.WithDefaultLevel(log.LevelInfo))
		return bundle.Pull(ctx, bundle.PullOptions{Release: rel, Arch: *arch, Signatures: *sigs, Key: key, Out: *out, ModTime: epoch, PlainHTTP: *plain, Logger: lg})
	default:
		return fmt.Errorf("unknown command %q (pull, check, manifest or images)", args[0])
	}
}

func manifest(args []string) error {
	fl := flag.NewFlagSet("bundle manifest", flag.ContinueOnError)
	image := fl.String("image", "", "the image, without a tag")
	dgst := fl.String("digest", "", "its pinned sha256 digest")
	out := fl.String("out", "", "the file to write")
	plain := fl.Bool("plain-http", false, "talk to the registry without TLS (a lab registry only)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	b, err := bundle.FetchManifest(ctx, *image, *dgst, *plain)
	if err != nil {
		return err
	}
	return os.WriteFile(*out, b, 0o644) // #nosec G306 G703 -- a public manifest, for the build to sign
}

// images writes every image release.yaml's bundle carries, "<image>
// <digest>" a line, sorted by image then digest; nothing when a pin isn't a
// digest.
func images(args []string, w io.Writer) error {
	fl := flag.NewFlagSet("bundle images", flag.ContinueOnError)
	relPath := fl.String("release", "", "release.yaml")
	if err := fl.Parse(args); err != nil {
		return err
	}
	relYAML, err := os.ReadFile(*relPath) // #nosec G304 G703 -- a build tool reading the file it was handed
	if err != nil {
		return err
	}
	rel, err := bundle.ParseRelease(relYAML)
	if err != nil {
		return err
	}
	pinned, err := rel.Images()
	if err != nil {
		return err
	}
	lines := make([]string, 0, len(pinned))
	for hexd, image := range pinned {
		lines = append(lines, image+" sha256:"+hexd)
	}
	sort.Strings(lines)
	for _, l := range lines {
		if _, err := fmt.Fprintln(w, l); err != nil {
			return err
		}
	}
	return nil
}
