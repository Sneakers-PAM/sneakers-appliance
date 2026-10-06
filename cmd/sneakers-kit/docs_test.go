// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
)

// TestEveryFlagIsDocumented keeps docs/build-your-image.md in step with the
// CLI: every flag of every command must appear there.
func TestEveryFlagIsDocumented(t *testing.T) {
	doc, err := os.ReadFile("../../docs/build-your-image.md")
	if err != nil {
		t.Fatal(err)
	}
	root := newRoot(release.Pins{}, &bytes.Buffer{}, &bytes.Buffer{})
	for _, cmd := range root.Commands() {
		cmd.Flags().VisitAll(func(f *pflag.Flag) {
			if f.Name == "help" {
				return
			}
			if !strings.Contains(string(doc), "`--"+f.Name+"`") {
				t.Errorf("docs/build-your-image.md doesn't document %s --%s", cmd.Name(), f.Name)
			}
		})
	}
}
