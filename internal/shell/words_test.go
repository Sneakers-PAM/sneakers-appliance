// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

func TestSplit(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{"status", []string{"status"}},
		{"  status   -o  json ", []string{"status", "-o", "json"}},
		{"status; id", []string{"status;", "id"}},
		{"status && reboot", []string{"status", "&&", "reboot"}},
		{"$(id)", []string{"$(id)"}},
		{"`id`", []string{"`id`"}},
		{"shell --reason 'look at kubelet'", []string{"shell", "--reason", "look at kubelet"}},
		{`shell --reason "it's \"broken\""`, []string{"shell", "--reason", `it's "broken"`}},
		{`a\ b`, []string{"a b"}},
		{`'$HOME'`, []string{"$HOME"}},
		{`""`, []string{""}},
		{"a\tb", []string{"a", "b"}},
		{"keys add > /etc/passwd", []string{"keys", "add", ">", "/etc/passwd"}},
		{"", nil},
	}
	for _, c := range cases {
		got, err := shell.Split(c.line)
		if err != nil {
			t.Fatalf("%q: %v", c.line, err)
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%q: got %q, want %q", c.line, got, c.want)
		}
	}
}

func TestSplitRefuses(t *testing.T) {
	for _, line := range []string{"a\nb", "a\x00b", "a\rb", "'open", `"open`, `trailing\`, "\xff\xfe", strings.Repeat("x", shell.MaxLine+1)} {
		if _, err := shell.Split(line); !codes.Is(err, codes.ShellParse) {
			t.Errorf("%q: got %v, want SHELL_PARSE", line, err)
		}
	}
	if _, err := shell.Split(strings.Repeat("x", shell.MaxLine)); err != nil {
		t.Fatalf("a line of exactly MaxLine: %v", err)
	}
}
