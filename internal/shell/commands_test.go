// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

type recordingBackend struct {
	calls []shell.Request
	reply map[string]shell.Result
	err   map[string]error
}

func (b *recordingBackend) Call(_ context.Context, r shell.Request) (shell.Result, error) {
	b.calls = append(b.calls, r)
	if err := b.err[r.Action]; err != nil {
		return shell.Result{}, err
	}
	if res, ok := b.reply[r.Action]; ok {
		return res, nil
	}
	return shell.Result{Text: "ok " + r.Action}, nil
}

func (b *recordingBackend) actions() []string {
	var out []string
	for _, c := range b.calls {
		out = append(out, c.Action)
	}
	return out
}

type run struct {
	out, err string
	b        *recordingBackend
	e        error
}

func runShellIn(t *testing.T, o shell.Origin, line, stdin string, b *recordingBackend) run {
	t.Helper()
	if b == nil {
		b = &recordingBackend{}
	}
	var out, errb bytes.Buffer
	e := &shell.Env{Origin: o, Backend: b, In: strings.NewReader(stdin), Out: &out, Err: &errb}
	err := shell.Run(context.Background(), e, line)
	return run{out.String(), errb.String(), b, err}
}

func runShell(t *testing.T, o shell.Origin, line string) (string, error) {
	t.Helper()
	r := runShellIn(t, o, line, "", nil)
	return r.out, r.e
}

func assertCode(t *testing.T, err error, symbol string) {
	t.Helper()
	c, ok := codes.Of(err)
	if !ok || codes.Symbol(c) != symbol {
		t.Fatalf("got %v, want %s", err, symbol)
	}
}

func TestConsoleOnlyCommandRefusedOverSSH(t *testing.T) {
	r := runShellIn(t, shell.OriginSSH, "network allow-list reset", "reset\n", nil)
	assertCode(t, r.e, "ACCESS_FORBIDDEN")
	if len(r.b.calls) != 0 {
		t.Fatalf("backend called: %v", r.b.actions())
	}
	r = runShellIn(t, shell.OriginSSH, "recovery-key add", "", nil)
	assertCode(t, r.e, "ACCESS_FORBIDDEN")
}

func TestSSHOnlyCommandRefusedOnConsole(t *testing.T) {
	for _, line := range []string{"login ABCD-EFGH", "shell --reason x", "elevation status", "elevation cert E-7K2Q", "setup recovery-key", "logs export", "support-bundle"} {
		_, err := runShell(t, shell.OriginConsole, line)
		assertCode(t, err, "ACCESS_FORBIDDEN")
	}
}

func TestEveryCommandParses(t *testing.T) {
	lines := map[shell.Origin][]string{
		shell.OriginSSH: {
			"status", "status -o json", "network show", "network confirm abc", "keys list", "keys list --admin bob",
			"keys remove SHA256:abc", "admins list", "admins add carol --role owner", "admins remove carol",
			"elevation status", "elevation status E-7K2Q", "elevation cert E-7K2Q", "tls show", "backup list",
			"restore", "upgrade status", "mcp off", "resources", "logs export", "support-bundle",
		},
		shell.OriginConsole: {"status", "network show", "keys list", "admins list", "tls show"},
	}
	for o, ls := range lines {
		for _, line := range ls {
			if _, err := runShell(t, o, line); err != nil {
				t.Errorf("%s %q: %v", o, line, err)
			}
		}
	}
	// The commands that read standard input or a confirmation.
	for _, c := range []struct {
		o           shell.Origin
		line, stdin string
	}{
		{shell.OriginSSH, "keys add", "ssh-ed25519 AAAA k\n"},
		{shell.OriginSSH, "setup recovery-key --label safe", "ssh-ed25519 AAAA k\n"},
		{shell.OriginConsole, "recovery-key add", "ssh-ed25519 AAAA k\n"},
		{shell.OriginSSH, "network set hostname=appliance.example.org", "y\n"},
		{shell.OriginConsole, "network allow-list reset", "reset\n"},
		{shell.OriginSSH, "login ABCD-EFGH", "y\n"},
		{shell.OriginSSH, `shell --minutes 30 --reason "investigate kubelet"`, ""},
		{shell.OriginSSH, "reboot", "reboot\n"},
		{shell.OriginConsole, "poweroff", "poweroff\n"},
	} {
		if r := runShellIn(t, c.o, c.line, c.stdin, nil); r.e != nil {
			t.Errorf("%s %q: %v", c.o, c.line, r.e)
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	_, err := runShell(t, shell.OriginSSH, "bash")
	assertCode(t, err, "SHELL_UNKNOWN")
	_, err = runShell(t, shell.OriginSSH, "status; id")
	if err == nil {
		t.Fatal("status; id ran")
	}
	_, err = runShell(t, shell.OriginSSH, "keys add --no-such-flag")
	assertCode(t, err, "SHELL_PARSE")
	_, err = runShell(t, shell.OriginSSH, "keys remove")
	assertCode(t, err, "SHELL_PARSE")
}

func TestKeysAddReadsStdin(t *testing.T) {
	r := runShellIn(t, shell.OriginSSH, "keys add", "ssh-ed25519 AAAA test key\n", nil)
	if r.e != nil {
		t.Fatal(r.e)
	}
	if got := string(r.b.calls[0].Stdin); got != "ssh-ed25519 AAAA test key\n" {
		t.Fatalf("stdin %q", got)
	}
}

func TestRebootNeedsTypedConfirmation(t *testing.T) {
	r := runShellIn(t, shell.OriginSSH, "reboot", "yes\n", nil)
	assertCode(t, r.e, "ACCESS_FORBIDDEN")
	if len(r.b.calls) != 0 {
		t.Fatal("rebooted without the typed word")
	}
	r = runShellIn(t, shell.OriginConsole, "poweroff", "poweroff\n", nil)
	if r.e != nil || strings.Join(r.b.actions(), ",") != "power.off" {
		t.Fatalf("%v %v", r.e, r.b.actions())
	}
}

func TestLoginAsksBeforeApproving(t *testing.T) {
	b := &recordingBackend{reply: map[string]shell.Result{"login.lookup": {Text: "Sign in the browser at 192.0.2.50 (test-agent) as alice?"}}}
	r := runShellIn(t, shell.OriginSSH, "login ABCD-EFGH", "n\n", b)
	if r.e != nil || strings.Join(b.actions(), ",") != "login.lookup" {
		t.Fatalf("approved without a yes: %v %v", r.e, b.actions())
	}
	if !strings.Contains(r.out, "192.0.2.50") {
		t.Fatalf("the prompt doesn't show the browser: %q", r.out)
	}
	b.calls = nil
	r = runShellIn(t, shell.OriginSSH, "login ABCD-EFGH", "y\n", b)
	if r.e != nil || strings.Join(b.actions(), ",") != "login.lookup,login.approve" {
		t.Fatalf("%v %v", r.e, b.actions())
	}
}

func TestShellRequestValidates(t *testing.T) {
	_, err := runShell(t, shell.OriginSSH, "shell")
	assertCode(t, err, "SHELL_PARSE")
	_, err = runShell(t, shell.OriginSSH, "shell --minutes 5 --reason x")
	assertCode(t, err, "SHELL_PARSE")
	r := runShellIn(t, shell.OriginSSH, `shell --minutes 30 --reason "investigate kubelet"`, "", nil)
	if r.e != nil || r.b.calls[0].Flags["minutes"] != "30" || r.b.calls[0].Flags["reason"] != "investigate kubelet" {
		t.Fatalf("%v %+v", r.e, r.b.calls)
	}
}

func TestNetworkSetConfirms(t *testing.T) {
	b := &recordingBackend{reply: map[string]shell.Result{"network.set": {Text: "Applied.", Data: map[string]string{"token": "t1"}}}}
	r := runShellIn(t, shell.OriginSSH, "network set hostname=appliance.example.org", "y\n", b)
	if r.e != nil || strings.Join(b.actions(), ",") != "network.set,network.confirm" || b.calls[1].Args[0] != "t1" {
		t.Fatalf("%v %v", r.e, b.calls)
	}
	b.calls = nil
	r = runShellIn(t, shell.OriginSSH, "network set hostname=appliance.example.org", "", b)
	if r.e != nil || strings.Join(b.actions(), ",") != "network.set" || !strings.Contains(r.out, "network confirm t1") {
		t.Fatalf("%v %v %q", r.e, b.actions(), r.out)
	}
}

func TestJSONOutputAndErrors(t *testing.T) {
	b := &recordingBackend{reply: map[string]shell.Result{"status": {Text: "fine", Data: map[string]any{"version": "0.1.0"}}}}
	r := runShellIn(t, shell.OriginSSH, "status -o json", "", b)
	var got map[string]any
	if err := json.Unmarshal([]byte(r.out), &got); err != nil || got["version"] != "0.1.0" {
		t.Fatalf("%q %v", r.out, err)
	}
	b = &recordingBackend{err: map[string]error{"tls.show": codes.New(codes.NotAvailable, "not available in this release")}}
	r = runShellIn(t, shell.OriginSSH, "tls show -o json", "", b)
	var je struct {
		Error struct{ Code, Message string } `json:"error"`
	}
	if err := json.Unmarshal([]byte(r.out), &je); err != nil || je.Error.Code != "NOT_AVAILABLE" {
		t.Fatalf("%q %v", r.out, err)
	}
	r = runShellIn(t, shell.OriginSSH, "tls show", "", b)
	if !strings.Contains(r.err, "NOT_AVAILABLE (3703): not available in this release") {
		t.Fatalf("stderr %q", r.err)
	}
}

func TestUnavailableBackend(t *testing.T) {
	b := &recordingBackend{err: map[string]error{"status": shell.ErrUnavailable}}
	r := runShellIn(t, shell.OriginSSH, "status", "", b)
	if !strings.Contains(r.err, "appliance services are unavailable") {
		t.Fatalf("stderr %q", r.err)
	}
}

func TestHelpHidesOtherOrigin(t *testing.T) {
	out, err := runShell(t, shell.OriginConsole, "help")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "support-bundle") || strings.Contains(out, "\n  login") {
		t.Fatalf("console help lists SSH-only commands:\n%s", out)
	}
}

func TestComplete(t *testing.T) {
	for typed, want := range map[string]string{
		"sta":            "status ",
		"network a":      "network allow-list ",
		"network allow-": "network allow-list ",
		"ke":             "keys ",
		"keys ":          "keys ",
		"zzz":            "zzz",
	} {
		if got := shell.Complete(shell.OriginConsole, typed); got != want {
			t.Errorf("Complete(%q) = %q, want %q", typed, got, want)
		}
	}
	if got := shell.Complete(shell.OriginSSH, "network a"); got != "network a" {
		t.Errorf("SSH completes a console-only command: %q", got)
	}
}
