// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package acmebox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/acme"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/kubeapi"
)

type fakeKube struct {
	secret    map[string][]byte
	secretErr error
	cert      string
	certErr   error
	paths     []string
}

func (k *fakeKube) Secret(_ context.Context, ns, name string) (map[string][]byte, error) {
	k.paths = append(k.paths, ns+"/"+name)
	return k.secret, k.secretErr
}

func (k *fakeKube) Object(_ context.Context, path string) ([]byte, error) {
	k.paths = append(k.paths, path)
	return []byte(k.cert), k.certErr
}

func box(t *testing.T, k *fakeKube) *Box {
	t.Helper()
	slot, man := t.TempDir(), t.TempDir()
	return &Box{Slot: slot, Manifests: man, Kube: k}
}

func installBundle(t *testing.T, b *Box, withCertManager bool) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(b.Slot, "bundle.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if withCertManager {
		if err := os.MkdirAll(filepath.Join(b.Slot, "manifests", "cert-manager"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func TestACMEIsAvailableOnlyWhereTheBundleRunsCertManager(t *testing.T) {
	b := box(t, &fakeKube{})
	if ok, reason := b.Available(); ok || !strings.Contains(reason, "product") {
		t.Fatalf("no product: %v %q", ok, reason)
	}
	installBundle(t, b, false)
	if ok, reason := b.Available(); ok || !strings.Contains(reason, "cert-manager") {
		t.Fatalf("a bundle without cert-manager: %v %q", ok, reason)
	}
	installBundle(t, b, true)
	if ok, reason := b.Available(); !ok || reason != "" {
		t.Fatalf("%v %q", ok, reason)
	}
}

func TestApplyWritesTheStackRootOnlyAndRemoveTakesItAway(t *testing.T) {
	b := box(t, &fakeKube{})
	ctx := context.Background()
	if err := b.Apply(ctx, []byte("kind: Issuer\n")); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(b.Manifests, acme.Stack, acme.Stack+".yaml")
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v: the stack holds the DNS token, so it's root only", st, err)
	}
	if err := b.Apply(ctx, []byte("kind: Issuer\nmetadata: {name: second}\n")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(p); !strings.Contains(string(got), "second") {
		t.Fatalf("not replaced: %s", got)
	}
	if err := b.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(p)); !os.IsNotExist(err) {
		t.Fatalf("the stack is still there: %v", err)
	}
	if err := b.Remove(ctx); err != nil {
		t.Fatalf("removing what isn't there is fine: %v", err)
	}
}

func TestStatusIsEmptyUntilCertManagerHasMadeTheSecret(t *testing.T) {
	k := &fakeKube{secretErr: fmt.Errorf("wrapped: %w", kubeapi.ErrNotFound), certErr: fmt.Errorf("wrapped: %w", kubeapi.ErrNotFound)}
	st, err := box(t, k).Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Ready || len(st.CertPEM) != 0 || st.Failure != "" {
		t.Fatalf("%+v", st)
	}
	if k.paths[0] != "sneakers/"+acme.SecretName {
		t.Fatalf("read %v", k.paths)
	}
}

func TestStatusCarriesThePairAndReady(t *testing.T) {
	k := &fakeKube{
		secret: map[string][]byte{"tls.crt": []byte("CRT"), "tls.key": []byte("KEY")},
		cert:   `{"status":{"conditions":[{"type":"Ready","status":"True"}]}}`,
	}
	st, err := box(t, k).Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Ready || string(st.CertPEM) != "CRT" || string(st.KeyPEM) != "KEY" || st.Failure != "" {
		t.Fatalf("%+v", st)
	}
	if k.paths[1] != "/apis/cert-manager.io/v1/namespaces/sneakers/certificates/"+acme.CertName { // scrub:allow=fqdn -- a Kubernetes API group
		t.Fatalf("read %v", k.paths)
	}
}

func TestAFailingIssueIsReportedWithCertManagersOwnWords(t *testing.T) {
	k := &fakeKube{
		secret: map[string][]byte{"tls.crt": []byte("CRT"), "tls.key": []byte("KEY")},
		cert: `{"status":{"lastFailureTime":"2026-11-15T10:00:00Z","conditions":[
			{"type":"Ready","status":"False","message":"Issuing certificate as Secret does not exist"},
			{"type":"Issuing","status":"True","message":"The certificate request has failed to complete and will be retried: Failed to wait for order resource to become ready: order is in \"errored\" state"}]}}`,
	}
	st, err := box(t, k).Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Ready || !strings.Contains(st.Failure, "errored") {
		t.Fatalf("%+v", st)
	}
	// A renewal that's just running isn't a failure.
	k.cert = `{"status":{"conditions":[{"type":"Ready","status":"True"},{"type":"Issuing","status":"True","message":"Renewing the certificate on request"}]}}`
	if st, _ := box(t, k).Status(context.Background()); st.Failure != "" || !st.Ready {
		t.Fatalf("%+v", st)
	}
}

func TestOtherReadErrorsAreErrors(t *testing.T) {
	k := &fakeKube{secretErr: fmt.Errorf("the API server is down")}
	if _, err := box(t, k).Status(context.Background()); err == nil {
		t.Fatal("a read that failed isn't an empty status")
	}
}
