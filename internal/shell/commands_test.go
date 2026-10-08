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
	for _, line := range []string{"shell --reason x", "setup recovery-key", "logs export", "support-bundle"} {
		_, err := runShell(t, shell.OriginConsole, line)
		assertCode(t, err, "ACCESS_FORBIDDEN")
	}
}

func TestEveryCommandParses(t *testing.T) {
	lines := map[shell.Origin][]string{
		shell.OriginSSH: {
			"status", "status -o json", "network show", "network confirm abc", "keys list", "keys list --admin bob",
			"admins list", "tls show", "backup list",
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
		{shell.OriginSSH, "setup recovery-key --label safe", "ssh-ed25519 AAAA k\n"},
		{shell.OriginConsole, "recovery-key add", "ssh-ed25519 AAAA k\n"},
		{shell.OriginSSH, "network set hostname=appliance.example.org", "y\n"},
		{shell.OriginConsole, "network allow-list reset", "reset\n"},
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
	_, err = runShell(t, shell.OriginSSH, "keys list --no-such-flag")
	assertCode(t, err, "SHELL_PARSE")
	_, err = runShell(t, shell.OriginSSH, "network confirm")
	assertCode(t, err, "SHELL_PARSE")
}

// Admins, keys and passwords change on :8443 only, where a step-up
// applies; the closed shell can't add or remove them, and sign-in codes
// are gone.
func TestAdminsAndKeysChangeOnlyOn8443(t *testing.T) {
	for _, line := range []string{"keys add", "keys remove SHA256:abc", "admins add carol", "admins remove carol", "login ABCD-EFGH", "elevation status", "elevation cert E-7K2Q"} {
		for _, o := range []shell.Origin{shell.OriginSSH, shell.OriginConsole} {
			r := runShellIn(t, o, line, "ssh-ed25519 AAAA k\n", nil)
			if len(r.b.calls) != 0 {
				t.Errorf("%s %q ran: %v %v", o, line, r.e, r.b.actions())
			}
		}
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

// The root shell: a challenge to take to :8443, then the code it gave;
// a wrong code may be typed again, and the right one's ticket opens the
// relay.
func TestTheRootShellTakesTheCodeAndRelays(t *testing.T) {
	b := &recordingBackend{
		reply: map[string]shell.Result{
			"rootshell.begin": {Text: "Paste K3M9-7QDA-2XPN-8RTW on :8443.", Data: map[string]string{"challenge": "K3M9-7QDA-2XPN-8RTW", "id": "R-ABCD"}},
			"rootshell.open":  {Data: map[string]string{"ticket": "tkt", "socket": "/run/sneakers/rootshell.sock"}},
		},
	}
	tries := 0
	var relayed []string
	var out bytes.Buffer
	e := &shell.Env{Origin: shell.OriginSSH, Backend: codeBackend{b: b, wrongFirst: &tries}, In: strings.NewReader("0000-0000\nQ7XD-2PNR\n"), Out: &out, Err: &out,
		RootShell: func(_ context.Context, socket, ticket string) error {
			relayed = append(relayed, socket, ticket)
			return nil
		}}
	if err := shell.Run(context.Background(), e, `shell --reason "kubelet"`); err != nil {
		t.Fatal(err)
	}
	if strings.Join(relayed, " ") != "/run/sneakers/rootshell.sock tkt" {
		t.Fatalf("relayed %v, out %q", relayed, out.String())
	}
	if got := strings.Join(b.actions(), ","); got != "rootshell.begin,rootshell.open,rootshell.open" {
		t.Fatalf("calls %s", got)
	}
	if b.calls[2].Args[0] != "K3M9-7QDA-2XPN-8RTW" || b.calls[2].Args[1] != "Q7XD-2PNR" || b.calls[0].Flags["reason"] != "kubelet" {
		t.Fatalf("calls %+v", b.calls)
	}
	if !strings.Contains(out.String(), "K3M9-7QDA-2XPN-8RTW") || !strings.Contains(out.String(), "tries left") || !strings.Contains(out.String(), "back in the menu") {
		t.Fatalf("out %q", out.String())
	}
}

// codeBackend refuses the first code as wrong.
type codeBackend struct {
	b          *recordingBackend
	wrongFirst *int
}

func (c codeBackend) Call(ctx context.Context, r shell.Request) (shell.Result, error) {
	res, err := c.b.Call(ctx, r)
	if r.Action == "rootshell.open" {
		*c.wrongFirst++
		if *c.wrongFirst == 1 {
			return shell.Result{}, codes.New(codes.RootCode, "that code doesn't match the challenge; 2 tries left")
		}
	}
	return res, err
}

func TestTheRootShellNeedsATerminal(t *testing.T) {
	r := runShellIn(t, shell.OriginSSH, "shell", "", nil)
	assertCode(t, r.e, "ACCESS_FORBIDDEN")
	if len(r.b.calls) != 0 {
		t.Fatalf("asked for a challenge without a terminal: %v", r.b.actions())
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
		"keys ":          "keys list ",
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

// The console's menu lists the console's commands, each with what it
// takes, from the same table the shell runs.
func TestCommandsDescribesTheConsoleSet(t *testing.T) {
	got := map[string]shell.Info{}
	for _, c := range shell.Commands(shell.OriginConsole) {
		got[c.Path] = c
	}
	if _, ok := got["login"]; ok {
		t.Fatal("login isn't a console command")
	}
	if c := got["network allow-list reset"]; c.Confirm != "reset" || c.Args {
		t.Fatalf("allow-list reset: %+v", c)
	}
	if c := got["keys list"]; c.Stdin || len(c.Flags) != 1 || c.Flags[0] != "admin" {
		t.Fatalf("keys list: %+v", c)
	}
	if c := got["recovery-key add"]; !c.Stdin {
		t.Fatalf("recovery-key add: %+v", c)
	}
	if c := got["backup"]; !c.Later {
		t.Fatalf("backup: %+v", c)
	}
	if len(got) != len(shell.Names(shell.OriginConsole)) {
		t.Fatalf("%d commands, %d names", len(got), len(shell.Names(shell.OriginConsole)))
	}
}
