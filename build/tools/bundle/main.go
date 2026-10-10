// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command bundle builds the airgap image bundle from release.yaml (pull) and
// checks a bundle directory against it in both directions (check), for
// build/bundle/build.sh. manifest writes the manifest or index bytes of one
// pinned image, which the release key (or a lab build's lab key) then
// signs, and images lists every image the bundle carries, "<image>
// <digest>" a line, refusing a placeholder digest.
//
// For the service images the release builds itself (build/release): sources
// lists each service's build block, fill puts the digests of the images
// built (one OCI layout per service, --layouts) in place of the
// placeholders, and push pushes one built image to its registry by digest.
// pull and manifest take --layouts too, and read a built image from its
// layout instead of a registry.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
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
		return fmt.Errorf("usage: bundle pull|check|manifest|images|sources|fill|push [flags]")
	}
	switch args[0] {
	case "manifest":
		return manifest(args[1:])
	case "images":
		return images(args[1:], os.Stdout)
	case "sources":
		return sources(args[1:], os.Stdout)
	case "fill":
		return fill(args[1:], os.Stdout)
	case "push":
		return push(args[1:])
	}
	fl := flag.NewFlagSet("bundle "+args[0], flag.ContinueOnError)
	relPath := fl.String("release", "", "release.yaml")
	keyPath := fl.String("key", "", "the org release key (cosign.pub)")
	arch := fl.String("arch", "amd64", "the architecture to pull")
	sigs := fl.String("signatures", "", "directory of <hex>.sigstore.json org signatures")
	out := fl.String("out", "", "the bundle directory (pull: empty or missing)")
	plain := fl.Bool("plain-http", false, "talk to registries without TLS (a lab registry only)")
	layouts := fl.String("layouts", "", "a directory of images the release built, an OCI layout per service (optional)")
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
		return bundle.Pull(ctx, bundle.PullOptions{Release: rel, Arch: *arch, Signatures: *sigs, Key: key, Out: *out, ModTime: epoch, PlainHTTP: *plain, Layouts: *layouts, Logger: lg})
	default:
		return fmt.Errorf("unknown command %q (pull, check, manifest, images, sources, fill or push)", args[0])
	}
}

func manifest(args []string) error {
	fl := flag.NewFlagSet("bundle manifest", flag.ContinueOnError)
	image := fl.String("image", "", "the image, without a tag")
	dgst := fl.String("digest", "", "its pinned sha256 digest")
	out := fl.String("out", "", "the file to write")
	plain := fl.Bool("plain-http", false, "talk to the registry without TLS (a lab registry only)")
	layouts := fl.String("layouts", "", "a directory of images the release built; a digest found there is read from its layout")
	if err := fl.Parse(args); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	local, err := bundle.Built(*layouts, *dgst)
	if err != nil {
		return err
	}
	var b []byte
	if local {
		b, err = bundle.LocalManifest(*layouts, *dgst)
	} else {
		b, err = bundle.FetchManifest(ctx, *image, *dgst, *plain)
	}
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

var (
	commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	repoRE   = regexp.MustCompile(`^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$`)
	wordRE   = regexp.MustCompile(`^[A-Za-z0-9._/@:+=-]+$`)
)

func readRelease(p string) (*bundle.Release, []byte, error) {
	b, err := os.ReadFile(p) // #nosec G304 G703 -- a build tool reading the file it was handed
	if err != nil {
		return nil, nil, err
	}
	rel, err := bundle.ParseRelease(b)
	return rel, b, err
}

func inRepo(p string) bool {
	return wordRE.MatchString(p) && !strings.HasPrefix(p, "/") && !slices.Contains(strings.Split(p, "/"), "..")
}

// sources writes the build block of each image the release builds (the
// services and the Job images), sorted by service: "<service>
// <image> <version> <repository> <commit> <dockerfile> <context> <target or -> <args
// KEY=value,... or ->". It refuses a service without one, or with a field
// a shell loop can't carry as one word.
func sources(args []string, w io.Writer) error {
	fl := flag.NewFlagSet("bundle sources", flag.ContinueOnError)
	relPath := fl.String("release", "", "release.yaml")
	if err := fl.Parse(args); err != nil {
		return err
	}
	rel, _, err := readRelease(*relPath)
	if err != nil {
		return err
	}
	built := rel.BuiltImages()
	names := make([]string, 0, len(built))
	for n := range built {
		names = append(names, n)
	}
	sort.Strings(names)
	var lines []string
	for _, n := range names {
		svc := built[n]
		b := svc.Build
		switch {
		case b == nil:
			return fmt.Errorf("services.%s has no build block", n)
		case !wordRE.MatchString(n) || !wordRE.MatchString(svc.Image):
			return fmt.Errorf("services.%s names no image", n)
		case !wordRE.MatchString(svc.Version):
			return fmt.Errorf("services.%s has no version", n)
		case !repoRE.MatchString(b.Repository):
			return fmt.Errorf("services.%s: build.repository %q isn't <owner>/<name>", n, b.Repository)
		case !commitRE.MatchString(b.Commit):
			return fmt.Errorf("services.%s: build.commit %q isn't a full commit", n, b.Commit)
		case !inRepo(b.Dockerfile) || !inRepo(b.Context):
			return fmt.Errorf("services.%s: build.dockerfile and build.context are paths in the repository", n)
		case b.Target != "" && !wordRE.MatchString(b.Target):
			return fmt.Errorf("services.%s: build.target %q", n, b.Target)
		}
		target, kv := "-", "-"
		if b.Target != "" {
			target = b.Target
		}
		if len(b.Args) > 0 {
			keys := make([]string, 0, len(b.Args))
			for k := range b.Args {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			pairs := make([]string, 0, len(keys))
			for _, k := range keys {
				p := k + "=" + b.Args[k]
				if !wordRE.MatchString(p) || strings.Contains(p, ",") || strings.Count(p, "=") != 1 {
					return fmt.Errorf("services.%s: build.args %s isn't KEY=value with no space or comma", n, k)
				}
				pairs = append(pairs, p)
			}
			kv = strings.Join(pairs, ",")
		}
		lines = append(lines, strings.Join([]string{n, svc.Image, svc.Version, b.Repository, b.Commit, b.Dockerfile, b.Context, target, kv}, " "))
	}
	for _, l := range lines {
		if _, err := fmt.Fprintln(w, l); err != nil {
			return err
		}
	}
	return nil
}

// fill writes release.yaml with the built images' digests in place of the
// placeholders (bundle.Fill).
func fill(args []string, w io.Writer) error {
	fl := flag.NewFlagSet("bundle fill", flag.ContinueOnError)
	relPath := fl.String("release", "", "release.yaml")
	layouts := fl.String("layouts", "", "the images the release built, an OCI layout per service")
	if err := fl.Parse(args); err != nil {
		return err
	}
	_, b, err := readRelease(*relPath)
	if err != nil {
		return err
	}
	out, err := bundle.Fill(b, *layouts)
	if err != nil {
		return err
	}
	_, err = w.Write(out)
	return err
}

// push pushes every service image the release built to the image its
// filled release.yaml names, by digest and with the version tag.
// Credentials come from REGISTRY_USERNAME and REGISTRY_PASSWORD, never
// from a flag.
func push(args []string) error {
	fl := flag.NewFlagSet("bundle push", flag.ContinueOnError)
	relPath := fl.String("release", "", "the filled release.yaml")
	layouts := fl.String("layouts", "", "the images the release built, an OCI layout per service")
	tag := fl.String("tag", "", "the version tag")
	plain := fl.Bool("plain-http", false, "talk to the registry without TLS (a lab registry only)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	rel, _, err := readRelease(*relPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	built := rel.BuiltImages()
	names := make([]string, 0, len(built))
	for n := range built {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		svc := built[n]
		if err := bundle.PushBuilt(ctx, bundle.PushOptions{Layouts: *layouts, Image: svc.Image, Digest: svc.Digest, Tag: *tag,
			Username: os.Getenv("REGISTRY_USERNAME"), Password: os.Getenv("REGISTRY_PASSWORD"), PlainHTTP: *plain}); err != nil {
			return err
		}
		fmt.Printf("pushed %s@%s (%s)\n", svc.Image, svc.Digest, *tag)
	}
	return nil
}
