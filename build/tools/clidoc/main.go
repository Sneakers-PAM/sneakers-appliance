// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command clidoc writes docs/cli.md, the closed shell's command
// reference, from its command tree. The shell's tests fail while the
// committed file isn't what this writes.
//
// Usage: go run ./build/tools/clidoc [--out docs/cli.md]
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

func main() {
	out := flag.String("out", "docs/cli.md", "the file to write")
	flag.Parse()
	if err := os.WriteFile(*out, []byte(shell.Reference()), 0o644); err != nil { // #nosec G306 -- a docs file in the repository
		fmt.Fprintln(os.Stderr, "clidoc:", err)
		os.Exit(1)
	}
	fmt.Println("clidoc: wrote", *out)
}
