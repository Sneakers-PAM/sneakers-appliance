// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command bundle builds the airgap image bundle from release.yaml (pull) and
// checks a bundle directory against it in both directions (check), for
// build/bundle/build.sh.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
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
		return fmt.Errorf("usage: bundle pull|check [flags]")
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
		return fmt.Errorf("unknown command %q (pull or check)", args[0])
	}
}
