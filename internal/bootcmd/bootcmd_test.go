// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bootcmd_test

import (
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/bootcmd"
)

var root = strings.Repeat("ab", 32)

func TestParse(t *testing.T) {
	p, err := bootcmd.Parse("sneakers.roothash=" + root + " sneakers.hashoffset=8192 sneakers.version=0.1.0 quiet console=tty0 console=ttyS0 panic=10 lockdown=integrity\x00")
	if err != nil || p.RootHash != root || p.HashOffset != 8192 || p.Version != "0.1.0" {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestParseRefusals(t *testing.T) {
	for name, line := range map[string]string{
		"no root hash": "sneakers.hashoffset=4096",
		"no offset":    "sneakers.roothash=" + root,
		"short hash":   "sneakers.roothash=abcd sneakers.hashoffset=4096",
		"upper hash":   "sneakers.roothash=" + strings.ToUpper(root) + " sneakers.hashoffset=4096",
		"odd offset":   "sneakers.roothash=" + root + " sneakers.hashoffset=4000",
		"twice":        "sneakers.roothash=" + root + " sneakers.roothash=" + root + " sneakers.hashoffset=4096",
		"negative":     "sneakers.roothash=" + root + " sneakers.hashoffset=-4096",
		"not a number": "sneakers.roothash=" + root + " sneakers.hashoffset=4k",
	} {
		if _, err := bootcmd.Parse(line); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
