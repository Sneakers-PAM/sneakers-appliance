// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd_test

import (
	"context"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevation"
)

// revoked asks OpenSSH's ssh-keygen, which reads the list as sshd does,
// whether key is on accessd's revocation list.
func (b *box) revoked(key sshKey) bool {
	b.t.Helper()
	bin, err := exec.LookPath("ssh-keygen")
	if err != nil {
		if os.Getenv("SNEAKERS_REQUIRE_TOOLS") != "" {
			b.t.Fatal("ssh-keygen isn't installed and SNEAKERS_REQUIRE_TOOLS is set")
		}
		b.t.Skip("ssh-keygen isn't installed")
	}
	file := filepath.Join(b.t.TempDir(), "key.pub")
	if err := os.WriteFile(file, []byte(key.line+"\n"), 0o600); err != nil {
		b.t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "-Q", "-f", filepath.Join(b.state, "ssh", elevation.RevokedFile), file).CombinedOutput() // #nosec G204 -- the test's own ssh-keygen
	if err != nil && !strings.Contains(string(out), "REVOKED") {
		b.t.Fatalf("ssh-keygen -Q: %v %s", err, out)
	}
	return strings.Contains(string(out), "REVOKED")
}

func (b *box) consoleAccess() accessv1connect.AccessServiceClient {
	hc, url := b.console()
	return accessv1connect.NewAccessServiceClient(hc, url)
}

// The key goes on the list in the store's own write, so a render that
// fails right after (netd is down) leaves a stale authorized keys file
// that sshd still refuses.
func TestARemovedKeyIsRevokedEvenWhenTheRenderFails(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	if b.revoked(b.keys["bob"]) {
		t.Fatal("bob's key is revoked before it's removed")
	}
	b.netd.mu.Lock()
	b.netd.down = true
	b.netd.mu.Unlock()
	if _, err := b.consoleAccess().RemoveKey(ctx, connect.NewRequest(&accessv1.RemoveKeyRequest{Admin: "bob", Fingerprint: b.keys["bob"].fp})); err != nil {
		t.Fatal(err)
	}
	if k := read(t, filepath.Join(b.run, "ssh", "authorized_keys", "bob")); !strings.Contains(k, b.keys["bob"].line) {
		t.Fatalf("the render didn't fail; the test proves nothing:\n%s", k)
	}
	if !b.revoked(b.keys["bob"]) {
		t.Fatal("the removed key isn't on the revocation list")
	}
	if b.revoked(b.keys["alice"]) {
		t.Fatal("a kept key is revoked")
	}
}

func TestRemovingAnAdminRevokesTheirKeys(t *testing.T) {
	b := newBox(t)
	if _, err := b.consoleAccess().RemoveAdmin(context.Background(), connect.NewRequest(&accessv1.RemoveAdminRequest{Name: "bob"})); err != nil {
		t.Fatal(err)
	}
	if !b.revoked(b.keys["bob"]) {
		t.Fatal("the removed admin's key isn't on the revocation list")
	}
}

// An elevated shell signed in with the key ends with it.
func TestRemovingAKeyEndsItsElevatedSession(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	bob := b.shellElevation("bob")
	req, err := bob.RequestElevation(ctx, connect.NewRequest(&accessv1.RequestElevationRequest{Minutes: 30, Reason: "investigate kubelet"}))
	if err != nil {
		t.Fatal(err)
	}
	id := req.Msg.GetElevation().GetId()
	console := b.elevationAs(0, "")
	if _, err := console.ApproveElevation(ctx, connect.NewRequest(&accessv1.ApproveElevationRequest{Id: id})); err != nil {
		t.Fatal(err)
	}
	cert, err := bob.GetElevationCertificate(ctx, connect.NewRequest(&accessv1.GetElevationCertificateRequest{Id: id}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := console.BeginElevatedSession(ctx, connect.NewRequest(&accessv1.BeginElevatedSessionRequest{Certificate: cert.Msg.GetCertificate(), Pid: 4242})); err != nil {
		t.Fatal(err)
	}
	if _, err := b.consoleAccess().RemoveKey(ctx, connect.NewRequest(&accessv1.RemoveKeyRequest{Admin: "bob", Fingerprint: b.keys["bob"].fp})); err != nil {
		t.Fatal(err)
	}
	if got := b.signalled(); !slices.Equal(got, []int{4242}) {
		t.Fatalf("signals %v", got)
	}
}

// A revoked key is refused wherever it's added, until an owner un-revokes
// it on :8443 (step-up, audited).
func TestARevokedKeyComesBackOnlyThroughAnOwnersUnrevoke(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	gone := b.keys["bob"]
	if _, err := b.consoleAccess().RemoveKey(ctx, connect.NewRequest(&accessv1.RemoveKeyRequest{Admin: "bob", Fingerprint: gone.fp})); err != nil {
		t.Fatal(err)
	}
	_, err := b.consoleAccess().AddKey(ctx, connect.NewRequest(&accessv1.AddKeyRequest{Admin: "bob", PublicKey: gone.line}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "ACCESS_KEY_REVOKED")

	hc, url := b.osadmin()
	api := osadminv1connect.NewAccessServiceClient(hc, url)
	cookie, csrf := b.signIn("alice")
	list, err := api.ListAdmins(ctx, withSession(connect.NewRequest(&osadminv1.ListAdminsRequest{}), cookie, csrf))
	if err != nil {
		t.Fatal(err)
	}
	rk := list.Msg.GetRevokedKeys()
	if len(rk) != 1 || rk[0].GetFingerprint() != gone.fp || rk[0].GetAdmin() != "bob" || rk[0].GetType() != "ssh-ed25519" || rk[0].GetRevoked() == nil {
		t.Fatalf("revoked keys %v", rk)
	}
	if _, err := api.UnrevokeKey(ctx, withSession(connect.NewRequest(&osadminv1.UnrevokeKeyRequest{Fingerprint: gone.fp}), cookie, csrf)); err != nil {
		t.Fatal(err)
	}
	if en := lastEntry(t, b.log, "access.key.unrevoke"); en.Actor != "alice" || en.Outcome != "ok" || en.Target != gone.fp {
		t.Fatalf("%+v", en)
	}
	if b.revoked(gone) {
		t.Fatal("the un-revoked key is still on the list")
	}
	if _, err := b.consoleAccess().AddKey(ctx, connect.NewRequest(&accessv1.AddKeyRequest{Admin: "bob", PublicKey: gone.line})); err != nil {
		t.Fatalf("the un-revoked key is refused: %v", err)
	}
	_, err = api.UnrevokeKey(ctx, withSession(connect.NewRequest(&osadminv1.UnrevokeKeyRequest{Fingerprint: gone.fp}), cookie, csrf))
	symbolIn(t, err, connect.CodeInvalidArgument, "ACCESS_KEY_TYPE")
}

// Each revocation names who removed the key: the admin on :8443 or in the
// closed shell, or the console.
func TestARevokedKeyNamesWhoRemovedIt(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	b.addAdmin("carol", access.RoleAdmin)
	b.addAdmin("dave", access.RoleAdmin)
	if _, err := b.shell("bob").RemoveKey(ctx, connect.NewRequest(&accessv1.RemoveKeyRequest{Fingerprint: b.keys["bob"].fp})); err != nil {
		t.Fatal(err)
	}
	if _, err := b.consoleAccess().RemoveKey(ctx, connect.NewRequest(&accessv1.RemoveKeyRequest{Admin: "dave", Fingerprint: b.keys["dave"].fp})); err != nil {
		t.Fatal(err)
	}
	hc, url := b.osadmin()
	api := osadminv1connect.NewAccessServiceClient(hc, url)
	cookie, csrf := b.signIn("alice")
	if _, err := api.RemoveAdmin(ctx, withSession(connect.NewRequest(&osadminv1.RemoveAdminRequest{Name: "carol"}), cookie, csrf)); err != nil {
		t.Fatal(err)
	}
	list, err := api.ListAdmins(ctx, withSession(connect.NewRequest(&osadminv1.ListAdminsRequest{}), cookie, csrf))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range list.Msg.GetRevokedKeys() {
		got[r.GetAdmin()] = r.GetRevokedBy()
	}
	want := map[string]string{"bob": "bob", "dave": access.ConsoleActor, "carol": "alice"}
	if !maps.Equal(got, want) {
		t.Fatalf("revoked by %v, want %v", got, want)
	}
}
