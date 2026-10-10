// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

func runWithSneakers(t *testing.T, line string) run {
	t.Helper()
	b := &recordingBackend{}
	var out, errb bytes.Buffer
	e := &shell.Env{Origin: shell.OriginSSH, Backend: b, In: strings.NewReader(""), Out: &out, Err: &errb, Product: sneakers, Switches: []string{"mcp"}}
	err := shell.Run(context.Background(), e, line)
	return run{out.String(), errb.String(), b, err}
}

// ? lists what a command takes: a group's sub-commands, a command's usage
// and the values its next argument takes, without asking the appliance.
func TestAQuestionMarkListsWhatACommandTakes(t *testing.T) {
	for line, wants := range map[string][]string{
		"sneakers mcp ?":    {"Usage:", "sneakers mcp [on|off]", "off", "turn the MCP off", "on", "turn the MCP on"},
		"sneakers ?":        {"mcp", "Show or set the MCP switch"},
		"network ?":         {"show", "set", "confirm", "Show the network settings"},
		"updates ?":         {"Usage:", "channel", "repo"},
		"updates channel ?": {"rc", "stable", "default"},
		"?":                 {"status", "network", "sneakers"},
		"keys ?":            {"list"},
		"disk cleanup ?":    {"Usage:", "disk cleanup"},
		"network set ?":     {"hostname=", "time-zone="},
		"help ?":            {"help"},
		"sneakers mcp on ?": {"Usage:"},
	} {
		r := runWithSneakers(t, line)
		if r.e != nil {
			t.Errorf("%q: %v %s", line, r.e, r.err)
			continue
		}
		for _, w := range wants {
			if !strings.Contains(r.out, w) {
				t.Errorf("%q lacks %q:\n%s", line, w, r.out)
			}
		}
		if len(r.b.calls) != 0 {
			t.Errorf("%q asked the appliance: %v", line, r.b.actions())
		}
	}
}

// A usage error prints its line, a blank line, the command's usage and
// examples, and a blank line; the code and message stay on the first
// line, and -o json keeps the bare error.
func TestAUsageErrorShowsTheCommandsUsage(t *testing.T) {
	r := runShellIn(t, shell.OriginSSH, "updates channel", "", nil)
	assertCode(t, r.e, "SHELL_PARSE")
	first, rest, ok := strings.Cut(r.err, "\n")
	if !ok || !strings.HasPrefix(first, "SHELL_PARSE (3701): updates takes channel") {
		t.Fatalf("first line %q", first)
	}
	if !strings.HasPrefix(rest, "\nUsage:\n  updates [channel rc|stable|default] [repo <owner>/<name>|default]") {
		t.Fatalf("no blank line and usage after the error:\n%s", r.err)
	}
	if !strings.Contains(rest, "Examples:\n  updates\n  updates channel rc\n") || strings.Contains(rest, "--help") || !strings.HasSuffix(r.err, "\n\n") {
		t.Fatalf("no examples, or no blank line after them:\n%q", r.err)
	}
	r = runShellIn(t, shell.OriginSSH, "updates channel -o json", "", nil)
	if strings.Contains(r.out, "Usage:") || !strings.Contains(r.out, `"code":"SHELL_PARSE"`) {
		t.Fatalf("json: %s", r.out)
	}
	r = runShellIn(t, shell.OriginSSH, "nosuch", "", nil)
	if strings.Contains(r.err, "Usage:") {
		t.Fatalf("an unknown command shows a usage:\n%s", r.err)
	}
}

// history outside an interactive session has nothing to list.
func TestHistoryWithoutATerminal(t *testing.T) {
	r := runShellIn(t, shell.OriginSSH, "history", "", nil)
	if r.e != nil || !strings.Contains(r.out, "no history") {
		t.Fatalf("%v %q %q", r.e, r.out, r.err)
	}
}

// fakePassword is a test proxy password, joined into a URL at run time.
const fakePassword = "hunter2"

// history masks what a line carries that's secret: a URL's password.
func TestHistoryMasksSecrets(t *testing.T) {
	got := shell.HistoryLine("network set https-proxy=http://proxyuser:" + fakePassword + "@192.0.2.8:3128 dns=192.0.2.53")
	if strings.Contains(got, fakePassword) || !strings.Contains(got, "http://proxyuser:***@192.0.2.8:3128") || !strings.Contains(got, "dns=192.0.2.53") {
		t.Fatalf("%q", got)
	}
}
