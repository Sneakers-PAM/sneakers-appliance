// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command k0spin prints the k0s SHA-256 release.yaml pins for an
// architecture, for the root build.
package main

import (
	"fmt"
	"os"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/bundle"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: k0spin <release.yaml> <arch>")
		os.Exit(2)
	}
	b, err := os.ReadFile(os.Args[1]) // #nosec G304 G703 -- a build tool reading the file it was handed
	if err != nil {
		fmt.Fprintln(os.Stderr, "k0spin:", err)
		os.Exit(1)
	}
	rel, err := bundle.ParseRelease(b)
	if err != nil {
		fmt.Fprintln(os.Stderr, "k0spin:", err)
		os.Exit(1)
	}
	sum, err := rel.K0sSHA256(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "k0spin:", err)
		os.Exit(1)
	}
	fmt.Println(sum)
}
