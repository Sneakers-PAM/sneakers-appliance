// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command svcchecklist writes the release's service repo checklist
// (docs/release.md#the-service-repo-checklist): for every repository
// release.yaml's services pin, plus sneakers-release and sneakers-web,
// whether the pinned commit's release is already published or still
// needs publishing, with what target and notes. It reads GitHub
// read-only, with no write to any service repo.
//
// Usage:
//
//	go run ./build/tools/svcchecklist --release release.yaml \
//	  --release-repo Sneakers-PAM/sneakers-release --release-commit <sha> \
//	  --web-repo Sneakers-PAM/sneakers-web --web-commit <sha> \
//	  [--prerelease] [--token $GH_TOKEN]
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/svcrelease"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "svcchecklist:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fl := flag.NewFlagSet("svcchecklist", flag.ContinueOnError)
	relPath := fl.String("release", "", "release.yaml")
	releaseRepo := fl.String("release-repo", "", "sneakers-release's owner/name")
	releaseCommit := fl.String("release-commit", "", "the sneakers-release commit this release pins")
	webRepo := fl.String("web-repo", "", "sneakers-web's owner/name")
	webCommit := fl.String("web-commit", "", "the sneakers-web commit this release pins")
	prerelease := fl.Bool("prerelease", false, "the appliance release being checked is itself a prerelease")
	token := fl.String("token", os.Getenv("GH_TOKEN"), "a GitHub token (GH_TOKEN by default); unauthenticated without one")
	out := fl.String("out", "", "write to this file instead of stdout")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *relPath == "" {
		return fmt.Errorf("--release is required")
	}
	b, err := os.ReadFile(*relPath) // #nosec G304 -- a build tool reading the file it was handed
	if err != nil {
		return err
	}
	rel, err := bundle.ParseRelease(b)
	if err != nil {
		return err
	}
	targets := svcrelease.Targets(rel, *releaseRepo, *releaseCommit, *webRepo, *webCommit)
	if len(targets) == 0 {
		return fmt.Errorf("release.yaml names no service with a build block, and neither --release-repo/--release-commit nor --web-repo/--web-commit were given")
	}
	api := svcrelease.API{Token: *token}
	items, err := svcrelease.CheckAll(context.Background(), api, targets, *prerelease)
	if err != nil {
		return err
	}
	md := svcrelease.Render(items)
	if *out == "" {
		fmt.Print(md)
		return nil
	}
	return os.WriteFile(*out, []byte(md), 0o644) // #nosec G306 G703 -- --out is this build tool's own flag, a workflow-chosen local path, never user input; the file is a job summary or notes fragment, never a secret
}
