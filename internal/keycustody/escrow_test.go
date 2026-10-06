// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package keycustody_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
)

func keyfileCustody(t *testing.T) *keycustody.Custody {
	t.Helper()
	needCryptsetup(t)
	kc := keycustody.New(keycustody.Deps{Disk: &fileDisk{dir: t.TempDir()}, SealedDir: t.TempDir()})
	if err := kc.Initialize(ctx, keycustody.ModeKeyfile, keycustody.SBOff); err != nil {
		t.Fatal(err)
	}
	return kc
}

type recovery struct {
	pub string
	id  age.Identity
}

func ed25519Key(t *testing.T) recovery {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, _ := ssh.NewPublicKey(pub)
	id, err := agessh.NewEd25519Identity(priv)
	if err != nil {
		t.Fatal(err)
	}
	return recovery{pub: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))), id: id}
}

func rsaKey(t *testing.T) recovery {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	sp, _ := ssh.NewPublicKey(&priv.PublicKey)
	id, err := agessh.NewRSAIdentity(priv)
	if err != nil {
		t.Fatal(err)
	}
	return recovery{pub: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))), id: id}
}

func TestSealAndUnseal(t *testing.T) {
	kc := keyfileCustody(t)
	if err := kc.Seal("vault-root", []byte("k")); err != nil {
		t.Fatal(err)
	}
	got, err := kc.Unseal("vault-root")
	if err != nil || string(got) != "k" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := kc.Unseal("nothing-here"); !codes.Is(err, codes.KeyCustodyNotFound) {
		t.Fatalf("got %v", err)
	}
	if err := kc.Seal("../escape", []byte("x")); !codes.Is(err, codes.KeyCustodyInvalid) {
		t.Fatalf("got %v", err)
	}
}

func TestEscrowOpensWithEachRecipient(t *testing.T) {
	kc := keyfileCustody(t)
	if err := kc.Seal("vault-root", []byte("root key bytes")); err != nil {
		t.Fatal(err)
	}
	ids := []recovery{ed25519Key(t), ed25519Key(t), rsaKey(t)}
	blob, err := kc.Escrow([]string{ids[0].pub, ids[1].pub, ids[2].pub})
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range ids {
		r, err := age.Decrypt(bytes.NewReader(blob), id.id)
		if err != nil {
			t.Fatalf("recipient %d: %v", i, err)
		}
		plain, _ := io.ReadAll(r)
		var c keycustody.EscrowContents
		if err := json.Unmarshal(plain, &c); err != nil || string(c.Items["vault-root"]) != "root key bytes" || len(c.StateKey) != keycustody.KeySize {
			t.Fatalf("recipient %d: %+v %v", i, c, err)
		}
	}
	other := ed25519Key(t)
	if _, err := age.Decrypt(bytes.NewReader(blob), other.id); err == nil {
		t.Fatal("a key that isn't a recipient opened the escrow")
	}
}

func TestEscrowRecipientRules(t *testing.T) {
	kc := keyfileCustody(t)
	k := ed25519Key(t).pub
	for name, rs := range map[string][]string{
		"none":         nil,
		"four":         {k, k, k, k},
		"security key": {"sk-ssh-ed25519 AAAAGnNrLXNzaC1lZDI1NTE5 test"},
		"not a key":    {"hello"},
	} {
		if _, err := kc.Escrow(rs); !codes.Is(err, codes.KeyCustodyRecipients) {
			t.Errorf("%s: want KEYCUSTODY_RECIPIENTS, got %v", name, err)
		}
	}
}
