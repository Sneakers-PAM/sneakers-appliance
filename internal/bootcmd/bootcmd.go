// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package bootcmd reads the appliance's parameters from a kernel command
// line: the UKI's .cmdline section on amd64, cmdline.txt on arm64.
package bootcmd

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Params are the sneakers.* parameters.
type Params struct {
	RootHash   string // 64 lowercase hex
	HashOffset int64
	Version    string
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Parse reads sneakers.roothash, sneakers.hashoffset and sneakers.version.
// Each must appear exactly once; the root hash and offset are required.
func Parse(cmdline string) (Params, error) {
	var p Params
	seen := map[string]bool{}
	for _, f := range strings.Fields(strings.TrimRight(cmdline, "\x00\n")) {
		k, v, ok := strings.Cut(f, "=")
		if !ok || !strings.HasPrefix(k, "sneakers.") {
			continue
		}
		if seen[k] {
			return Params{}, fmt.Errorf("bootcmd: %s appears twice", k)
		}
		seen[k] = true
		switch k {
		case "sneakers.roothash":
			if !hex64.MatchString(v) {
				return Params{}, fmt.Errorf("bootcmd: sneakers.roothash %q isn't 64 lowercase hex", v)
			}
			p.RootHash = v
		case "sneakers.hashoffset":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n <= 0 || n%4096 != 0 {
				return Params{}, fmt.Errorf("bootcmd: sneakers.hashoffset %q isn't a positive multiple of 4096", v)
			}
			p.HashOffset = n
		case "sneakers.version":
			p.Version = v
		}
	}
	if p.RootHash == "" || p.HashOffset == 0 {
		return Params{}, fmt.Errorf("bootcmd: the command line has no sneakers.roothash and sneakers.hashoffset")
	}
	return p, nil
}
