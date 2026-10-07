// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell_test

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

// FuzzLineNeverExecs: whatever bytes arrive, a line splits into plain words
// with no control characters, and running it only ever makes the backend
// calls of the command table. The shell links nothing that starts a program
// (TestNoProgramExec), so these calls are its only effect.
func FuzzLineNeverExecs(f *testing.F) {
	for _, s := range []string{"status; id", "status && reboot", "$(id)", "`id`", "a\nb", "a\x00b", strings.Repeat("x", 70000),
		"keys add < /etc/shadow", "shell --reason '$(reboot)'", "network set 'hostname=a.example.org;id'", "login ABCD-EFGH | sh",
		"/bin/sh", "sh -c id", "help", "keys add --admin=\"bob\" -o json", "elevation cert E-7K2Q > ~/.ssh/x"} {
		f.Add(s)
	}
	known := shell.Actions()
	f.Fuzz(func(t *testing.T, line string) {
		if words, err := shell.Split(line); err == nil {
			for _, w := range words {
				if strings.ContainsFunc(w, func(r rune) bool { return r != '\t' && (r < 0x20 || r == 0x7f) }) {
					t.Fatalf("line %q gave a word with a control character: %q", line, w)
				}
			}
		}
		for _, o := range []shell.Origin{shell.OriginSSH, shell.OriginConsole} {
			b := &recordingBackend{}
			e := &shell.Env{Origin: o, Backend: b, In: strings.NewReader("y\n"), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
			_ = shell.Run(context.Background(), e, line)
			for _, r := range b.calls {
				if !slices.Contains(known, r.Action) {
					t.Fatalf("line %q made an unknown call %q", line, r.Action)
				}
			}
		}
	})
}
