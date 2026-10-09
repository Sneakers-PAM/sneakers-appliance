// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command k0spin prints the SHA-256 release.yaml pins for an architecture's
// k0s binary, or its helm binary (nothing when the release ships no helm),
// for the product build.
package main

import (
	"fmt"
	"os"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/bundle"
)

func main() {
	if len(os.Args) != 3 && (len(os.Args) != 4 || (os.Args[3] != "k0s" && os.Args[3] != "helm")) {
		fmt.Fprintln(os.Stderr, "usage: k0spin <release.yaml> <arch> [k0s|helm]")
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
	pin := rel.K0sSHA256
	if len(os.Args) == 4 && os.Args[3] == "helm" {
		pin = rel.HelmSHA256
	}
	sum, err := pin(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "k0spin:", err)
		os.Exit(1)
	}
	if sum != "" {
		fmt.Println(sum)
	}
}
