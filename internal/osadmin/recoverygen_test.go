// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
)

// The box makes the recovery key pair: the public half becomes a recovery
// key the escrow is encrypted to, and the private key leaves in the answer
// only.
func TestGenerateRecoveryKey(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	su := osadminv1connect.NewSetupServiceClient(alice.hc, b.ts.URL)

	out, err := su.GenerateRecoveryKey(ctx, connect.NewRequest(&osadminv1.GenerateRecoveryKeyRequest{Label: "offline safe"}))
	if err != nil {
		t.Fatal(err)
	}
	m := out.Msg
	raw, err := ssh.ParseRawPrivateKey([]byte(m.GetPrivateKey()))
	if err != nil {
		t.Fatalf("the private key is OpenSSH: %v", err)
	}
	priv, ok := raw.(*ed25519.PrivateKey)
	if !ok {
		t.Fatalf("an ed25519 key, got %T", raw)
	}
	spk, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(spk))); !strings.HasPrefix(m.GetPublicKey(), got) {
		t.Fatalf("the public key %q is the private key's (%q)", m.GetPublicKey(), got)
	}
	rk := m.GetRecoveryKey()
	if rk.GetFingerprint() != ssh.FingerprintSHA256(spk) || rk.GetType() != ssh.KeyAlgoED25519 || rk.GetLabel() != "offline safe" || rk.GetSetBy() != "alice" {
		t.Fatalf("recovery key %v", rk)
	}
	if !strings.HasPrefix(m.GetFileName(), "sneakers-recovery-") {
		t.Fatalf("file name %q", m.GetFileName())
	}

	st := b.store.Read()
	if len(st.RecoveryKeys) != 1 || st.RecoveryKeys[0].Fingerprint != rk.GetFingerprint() {
		t.Fatalf("stored %v", st.RecoveryKeys)
	}
	if !slices.ContainsFunc(b.init.escrowFor, func(r string) bool {
		return strings.HasPrefix(r, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(spk))))
	}) {
		t.Fatalf("the escrow goes to the new key: %v", b.init.escrowFor)
	}
	if e := lastEntry(t, b.log, "setup.recovery-key.generate"); e.Outcome != "ok" || e.Target != rk.GetFingerprint() {
		t.Fatalf("audited %+v", e)
	}

	// The private key is nowhere on the state volume: not the store, the
	// audit log or the escrow.
	body := privateKeyBody(t, m.GetPrivateKey())
	if err := filepath.WalkDir(b.state, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(p) // #nosec G304 -- the test's own state dir
		if err != nil {
			return err
		}
		if bytes.Contains(data, body) {
			t.Errorf("%s holds the private key", p)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	got, err := su.GetSetup(ctx, connect.NewRequest(&osadminv1.GetSetupRequest{}))
	if err != nil || len(got.Msg.GetRecoveryKeys()) != 1 {
		t.Fatalf("%v %v", got, err)
	}
}

// The same limit as AddRecoveryKey: three at most, generated or pasted.
func TestGenerateRecoveryKeyKeepsTheLimit(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	su := osadminv1connect.NewSetupServiceClient(alice.hc, b.ts.URL)
	if _, err := su.AddRecoveryKey(ctx, connect.NewRequest(&osadminv1.AddRecoveryKeyRequest{PublicKey: newKey(t).line})); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := su.GenerateRecoveryKey(ctx, connect.NewRequest(&osadminv1.GenerateRecoveryKeyRequest{})); err != nil {
			t.Fatal(err)
		}
		b.clk.Advance(1e9)
	}
	_, err := su.GenerateRecoveryKey(ctx, connect.NewRequest(&osadminv1.GenerateRecoveryKeyRequest{}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "ACCESS_RECOVERY_KEY_LIMIT")
	if e := lastEntry(t, b.log, "setup.recovery-key.generate"); e.Outcome == "ok" {
		t.Fatal("the refusal is audited")
	}
}

func TestGenerateRecoveryKeyIsForOwners(t *testing.T) {
	b := newBox(t, true)
	bob := b.browser()
	bob.signIn("bob")
	_, err := osadminv1connect.NewSetupServiceClient(bob.hc, b.ts.URL).GenerateRecoveryKey(context.Background(), connect.NewRequest(&osadminv1.GenerateRecoveryKeyRequest{}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
}

func TestGenerateRecoveryKeyTakesAOneLineLabel(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	su := osadminv1connect.NewSetupServiceClient(alice.hc, b.ts.URL)
	_, err := su.GenerateRecoveryKey(context.Background(), connect.NewRequest(&osadminv1.GenerateRecoveryKeyRequest{Label: "safe\nmore"}))
	symbolIn(t, err, connect.CodeInvalidArgument, "ACCESS_NAME")
	if n := len(b.store.Read().RecoveryKeys); n != 0 {
		t.Fatalf("%d recovery keys", n)
	}
}

// privateKeyBody is the PEM block's base64 body, joined, which is what a
// copy of the key anywhere would contain.
func privateKeyBody(t *testing.T, pemText string) []byte {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(pemText), "\n")
	if len(lines) < 3 {
		t.Fatalf("not a PEM block: %q", pemText)
	}
	return []byte(lines[1])
}
