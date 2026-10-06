// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command check refuses a UKI whose PCR 11 the box couldn't predict: it
// must carry exactly .linux, .initrd, .cmdline, .osrel, .uname and .sbat.
// build/uki/assemble.sh runs it on every image it makes.
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/ukipcr"
)

var want = []string{".linux", ".osrel", ".cmdline", ".initrd", ".uname", ".sbat"}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: check <uki>")
		os.Exit(2)
	}
	b, err := os.ReadFile(os.Args[1]) // #nosec G304 G703 -- a build tool reading the file it was handed
	if err != nil {
		fmt.Fprintln(os.Stderr, "uki check:", err)
		os.Exit(1)
	}
	p, err := ukipcr.Predict(b)
	if err != nil {
		fmt.Fprintln(os.Stderr, "uki check:", err)
		os.Exit(1)
	}
	if strings.Join(p.Sections, " ") != strings.Join(want, " ") {
		fmt.Fprintf(os.Stderr, "uki check: sections %v, want exactly %v\n", p.Sections, want)
		os.Exit(1)
	}
	fmt.Printf("uki check: %s, PCR 11 %s\n", strings.Join(p.Sections, " "), hex.EncodeToString(p.Value))
}
