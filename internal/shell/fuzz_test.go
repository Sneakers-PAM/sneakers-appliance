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

// FuzzSplitNeverShells pins Review Focus 2: whatever bytes arrive, a line
// is plain words, and no word sequence resolves to a program exec. Running
// the line goes only to the backend.
func FuzzSplitNeverShells(f *testing.F) {
	for _, s := range []string{"status; id", "status && reboot", "$(id)", "`id`", "a\nb", "a\x00b", strings.Repeat("x", 70000),
		"keys add < /etc/shadow", "shell --reason '$(reboot)'", "network set 'hostname=a.example.org;id'", "login ABCD-EFGH | sh"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		words, err := shell.Split(line)
		if err != nil {
			return
		}
		cmd := shell.Resolve(words)
		if cmd != nil && cmd.ExecsProgram() {
			t.Fatalf("line %q resolved to a program exec", line)
		}
		b := &recordingBackend{}
		e := &shell.Env{Origin: shell.OriginSSH, Backend: b, In: strings.NewReader(""), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
		_ = shell.Run(context.Background(), e, line)
		for _, r := range b.calls {
			for _, a := range r.Args {
				if strings.ContainsAny(a, "\n\x00") {
					t.Fatalf("an argument with a control character reached the backend: %q", a)
				}
			}
		}
	})
}
