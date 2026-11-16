// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxsecrets"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/rootrotate"
)

const rootKeyProduct = `format: 2
box_secrets:
  - secret: sneakers/sneakers-box
    keys:
      - {key: VAULT_ROOT_KEK, generate: key32}
      - {key: TOTP_ENC_KEY, generate: key32}
escrow:
  - name: vault-root-key
    secret: sneakers/sneakers-box
    key: VAULT_ROOT_KEK
    previous: VAULT_ROOT_KEK_PREVIOUS
    restart: [sneakers/deployment/sneakers-vault]
  - name: totp-key
    secret: sneakers/sneakers-box
    key: TOTP_ENC_KEY
`

// rootKeyBox is the box and a vault that reports what the stack it was started
// with says: verified when it holds a previous key, none when it doesn't.
type rootKeyBox struct {
	*box
	alice  *browser
	store  *boxsecrets.Store
	mu     sync.Mutex
	vault  string // "ok" or "failing"
	startd time.Time
	// restarts counts the vault's restarts.
	restarts int
}

func (r *rootKeyBox) Applied(context.Context) error { return nil }
func (r *rootKeyBox) Restart(context.Context, string, string, string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.restarts++
	r.startd = time.Now().Add(time.Millisecond)
	return nil
}
func (r *rootKeyBox) RolledOut(context.Context, string, string, string) (string, bool, error) {
	return "", true, nil
}

func (r *rootKeyBox) RootKeyStatus(_ context.Context, _, _, _ string, notBefore time.Time) (rootrotate.VaultStatus, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.startd.Before(notBefore) || r.restarts == 0 {
		return rootrotate.VaultStatus{}, errors.New("no pod yet")
	}
	if r.vault == "failing" {
		return rootrotate.VaultStatus{State: rootrotate.StateFailed, Pending: 1}, nil
	}
	b, _ := os.ReadFile(filepath.Join(r.state, "k0s-manifests", productspec.BoxSecretsStack, productspec.BoxSecretsStack+".yaml"))
	if strings.Contains(string(b), "VAULT_ROOT_KEK_PREVIOUS") {
		return rootrotate.VaultStatus{State: rootrotate.StateVerified}, nil
	}
	return rootrotate.VaultStatus{State: rootrotate.StateNone}, nil
}

// SecretKey reads the live Secret as the stack carries it: the store's value.
func (r *rootKeyBox) SecretKey(_ context.Context, _, _, key string) (string, error) {
	name := map[string]string{"VAULT_ROOT_KEK": "vault-root-key", "TOTP_ENC_KEY": "totp-key"}[key]
	v, found, err := r.store.Value(filepath.Join(r.state, "product", "current"), name)
	if err != nil || !found {
		return "", errors.New("not found")
	}
	return v, nil
}
func (r *rootKeyBox) ServiceGet(context.Context, string, string, string) ([]byte, error) {
	return nil, errors.New("not up")
}

func newRootKeyBox(t *testing.T) *rootKeyBox {
	t.Helper()
	r := &rootKeyBox{vault: "ok"}
	b := newBox(t, true, func(b *box, o *osadmin.Options) {
		r.store = &boxsecrets.Store{Dir: filepath.Join(b.state, "platform"), Manifests: filepath.Join(b.state, "k0s-manifests")}
		o.BoxSecrets, o.RootKeys, o.RootKeyStatus, o.TelemetryWorkloads, o.Exposed = r.store, r.store, r, r, r
		o.RootRotatePoll, o.RootRotateBound = 5*time.Millisecond, 500*time.Millisecond
	})
	r.box = b
	r.alice = b.browser()
	r.alice.signIn("alice")
	r.alice.installProduct(t, "0.2.0")
	slot := filepath.Join(b.state, "product", "current")
	if err := os.WriteFile(filepath.Join(slot, productspec.File), []byte(rootKeyProduct), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.store.Ensure(slot); err != nil {
		t.Fatal(err)
	}
	su := osadminv1connect.NewSetupServiceClient(r.alice.hc, b.ts.URL)
	if _, err := su.AddRecoveryKey(context.Background(), connect.NewRequest(&osadminv1.AddRecoveryKeyRequest{PublicKey: newKey(t).line, Label: "safe"})); err != nil {
		t.Fatal(err)
	}
	if _, err := su.DownloadEscrow(context.Background(), connect.NewRequest(&osadminv1.DownloadEscrowRequest{})); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *rootKeyBox) client() osadminv1connect.RootKeyServiceClient {
	return osadminv1connect.NewRootKeyServiceClient(r.alice.hc, r.ts.URL)
}

func (r *rootKeyBox) waitState(t *testing.T, want string) *osadminv1.GetRootKeyRotationResponse {
	t.Helper()
	for i := 0; i < 400; i++ {
		res, err := r.client().GetRootKeyRotation(context.Background(), connect.NewRequest(&osadminv1.GetRootKeyRotationRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		if res.Msg.GetState() == want {
			return res.Msg
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the rotation never reached %s", want)
	return nil
}

func (r *rootKeyBox) sealedKey(name string) string {
	r.init.mu.Lock()
	defer r.init.mu.Unlock()
	return string(r.init.sealed[name])
}

// A rotation moves the key, replaces the sealed copy only after the vault
// verified, retires the staging item by name and leaves the box with the new
// key alone.
func TestAnOwnerRotatesTheVaultRootKey(t *testing.T) {
	r := newRootKeyBox(t)
	slot := filepath.Join(r.state, "product", "current")
	old, _, _ := r.store.Value(slot, "vault-root-key")
	if got := r.sealedKey("product-sneakers-vault-root-key"); got != old {
		t.Fatalf("before: sealed %q", got)
	}
	if _, err := r.client().RotateRootKey(context.Background(), connect.NewRequest(&osadminv1.RotateRootKeyRequest{})); err != nil {
		t.Fatal(err)
	}
	r.waitState(t, "done")
	now, _, _ := r.store.Value(slot, "vault-root-key")
	if now == old || now == "" {
		t.Fatal("the key didn't move")
	}
	if got := r.sealedKey("product-sneakers-vault-root-key"); got != now {
		t.Fatalf("the sealed copy is not the new key")
	}
	if r.sealedKey("product-sneakers-vault-root-key-next") != "" || strings.Join(r.init.retired, ",") != "product-sneakers-vault-root-key-next" {
		t.Fatalf("the staging item: retired %v", r.init.retired)
	}
	if held, _ := r.store.Rotating(slot); held {
		t.Fatal("the previous key is still held")
	}
	if r.restarts != 2 {
		t.Fatalf("the vault restarted %d times, want 2 (to verify, then on the new key alone)", r.restarts)
	}
}

// A vault that doesn't verify leaves both keys, the old sealed copy and the
// staging item as they were; the box refuses to apply the product until the
// rotation is finished.
func TestAFailedRootKeyRotationKeepsBothKeysAndHoldsTheProduct(t *testing.T) {
	r := newRootKeyBox(t)
	slot := filepath.Join(r.state, "product", "current")
	old, _, _ := r.store.Value(slot, "vault-root-key")
	r.vault = "failing"
	if _, err := r.client().RotateRootKey(context.Background(), connect.NewRequest(&osadminv1.RotateRootKeyRequest{})); err != nil {
		t.Fatal(err)
	}
	st := r.waitState(t, "stopped")
	if st.GetWhy() == "" || strings.Contains(st.GetWhy(), old) {
		t.Fatalf("why: %q", st.GetWhy())
	}
	if held, _ := r.store.Rotating(slot); !held {
		t.Fatal("the previous key was dropped")
	}
	if got := r.sealedKey("product-sneakers-vault-root-key"); got != old {
		t.Fatal("the sealed copy of the old key changed")
	}
	if r.sealedKey("product-sneakers-vault-root-key-next") == "" || len(r.init.retired) != 0 {
		t.Fatal("the staging item went")
	}
	// An escrow download in the meantime doesn't replace the old key's copy.
	su := osadminv1connect.NewSetupServiceClient(r.alice.hc, r.ts.URL)
	if _, err := su.DownloadEscrow(context.Background(), connect.NewRequest(&osadminv1.DownloadEscrowRequest{})); err != nil {
		t.Fatal(err)
	}
	if got := r.sealedKey("product-sneakers-vault-root-key"); got != old {
		t.Fatal("an escrow download replaced the old key's sealed copy mid-rotation")
	}
	// The vault recovers; a new request carries on and finishes.
	r.vault = "ok"
	if _, err := r.client().RotateRootKey(context.Background(), connect.NewRequest(&osadminv1.RotateRootKeyRequest{})); err != nil {
		t.Fatal(err)
	}
	r.waitState(t, "done")
	now, _, _ := r.store.Value(slot, "vault-root-key")
	if got := r.sealedKey("product-sneakers-vault-root-key"); got != now || now == old {
		t.Fatal("the resumed rotation didn't end on the new key")
	}
}

// A product whose bundle names no previous key can't rotate.
func TestAProductWithoutAPreviousKeyCantRotate(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	alice.installProduct(t, "0.2.0")
	c := osadminv1connect.NewRootKeyServiceClient(alice.hc, b.ts.URL)
	if _, err := c.RotateRootKey(context.Background(), connect.NewRequest(&osadminv1.RotateRootKeyRequest{})); err == nil {
		t.Fatal("rotated with nothing to rotate")
	}
	res, err := c.GetRootKeyRotation(context.Background(), connect.NewRequest(&osadminv1.GetRootKeyRotationRequest{}))
	if err != nil || res.Msg.GetAvailable() || res.Msg.GetState() != "none" {
		t.Fatalf("%v %v", res, err)
	}
}
