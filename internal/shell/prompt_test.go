// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell_test

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

type termIO struct {
	in  io.Reader
	out bytes.Buffer
}

func (t *termIO) Read(p []byte) (int, error)  { return t.in.Read(p) }
func (t *termIO) Write(p []byte) (int, error) { return t.out.Write(p) }

// On the interactive terminal a command's own question (the root shell's
// "Code:") is its own line: the menu's prompt doesn't follow it on the same
// line, and the menu comes back on a new line after it.
func TestTheCodePromptAndTheMenuPromptAreSeparateLines(t *testing.T) {
	b := &recordingBackend{
		reply: map[string]shell.Result{
			"rootshell.begin": {Text: "Paste K3M9-7QDA-2XPN-8RTW on :8443.", Data: map[string]string{"challenge": "K3M9-7QDA-2XPN-8RTW", "id": "R-ABCD"}},
			"rootshell.open":  {Data: map[string]string{"ticket": "tkt", "socket": "/run/sneakers/rootshell.sock"}},
		},
	}
	rw := &termIO{in: strings.NewReader("shell\rQ7XD-2PNR\rexit\r")}
	e := &shell.Env{Origin: shell.OriginSSH, Backend: b, RootShell: func(context.Context, string, string) error { return nil }}
	if err := shell.Interactive(context.Background(), e, rw, "alice@box1> "); err != nil {
		t.Fatal(err)
	}
	out := rw.out.String()
	if strings.Contains(out, "Code: alice@box1> ") || !strings.Contains(out, "Code: Q7XD-2PNR\r\n") {
		t.Fatalf("the code prompt runs into the menu's:\n%q", out)
	}
	if !strings.Contains(out, "back in the menu.\r\nalice@box1> ") {
		t.Fatalf("the menu prompt doesn't start a new line:\n%q", out)
	}
	if b.calls[1].Args[1] != "Q7XD-2PNR" {
		t.Fatalf("calls %+v", b.calls)
	}
}
