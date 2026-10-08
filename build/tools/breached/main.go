// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command breached builds internal/credentials/breached.bin from password
// lists: every entry of 12 characters or more, in lower case, as the first
// 6 bytes of its SHA-256, sorted and without repeats. Shorter entries are
// left out because the box refuses passwords under 12 characters anyway.
// scripts/breached-passwords.sh fetches the pinned lists and runs it.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	minLength  = 12
	prefixSize = 6
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: breached <out.bin> <list>...")
		os.Exit(2)
	}
	var entries [][prefixSize]byte
	for _, p := range os.Args[2:] {
		f, err := os.Open(p) // #nosec G304 G703 -- a build tool reading the lists it was handed
		if err != nil {
			fmt.Fprintln(os.Stderr, "breached:", err)
			os.Exit(1)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.ToLower(strings.TrimRight(sc.Text(), "\r"))
			if utf8.RuneCountInString(line) < minLength {
				continue
			}
			sum := sha256.Sum256([]byte(line))
			entries = append(entries, [prefixSize]byte(sum[:prefixSize]))
		}
		_ = f.Close()
		if err := sc.Err(); err != nil {
			fmt.Fprintln(os.Stderr, "breached:", err)
			os.Exit(1)
		}
	}
	slices.SortFunc(entries, func(a, b [prefixSize]byte) int { return bytes.Compare(a[:], b[:]) })
	entries = slices.Compact(entries)
	var out bytes.Buffer
	for _, e := range entries {
		out.Write(e[:])
	}
	if err := os.WriteFile(os.Args[1], out.Bytes(), 0o644); err != nil { // #nosec G306 -- a file checked into the repository
		fmt.Fprintln(os.Stderr, "breached:", err)
		os.Exit(1)
	}
	fmt.Printf("breached: %d entries\n", len(entries))
}
