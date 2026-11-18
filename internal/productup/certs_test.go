// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productup_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productup"
)

// tlsStack is an always-on stack that declares cert-manager objects next to a
// ConfigMap, as the Sneakers stack does for its services' certificates.
const tlsStack = `apiVersion: v1
kind: ConfigMap
metadata: {name: app-tls-config, namespace: app}
---
apiVersion: cert-manager.io/v1  # scrub:allow=fqdn -- a Kubernetes API group
kind: Issuer
metadata: {name: app-ca, namespace: app}
spec: {selfSigned: {}}
---
apiVersion: cert-manager.io/v1  # scrub:allow=fqdn -- a Kubernetes API group
kind: Certificate
metadata: {name: app-identity, namespace: app}
spec: {secretName: app-identity-tls, issuerRef: {name: app-ca}}
`

// certProbe is a phased slot whose always-on stack app-tls declares
// cert-manager objects, with the API up and every always-on stack applied the
// way k0s would at start; certsOK is whether cert-manager accepted its objects.
func certProbe(t *testing.T, certsOK bool) (*productup.Probe, *fakeCluster, string, *time.Time) {
	t.Helper()
	c := newCluster()
	c.apiUp, c.certReady, c.certCRD = true, certsOK, true
	p, manifests := phasedProbe(t, c)
	if err := os.MkdirAll(filepath.Join(p.Slot, "manifests", "app-tls"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.Slot, "manifests", "app-tls", "tls.yaml"), []byte(tlsStack), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, st := range []string{"app", "edge", "app-tls"} {
		c.apply(t, p.Slot, st)
	}
	c.setReady("Deployment edge/edge", true, "")
	now := time.Unix(1_000_000, 0)
	p.Now = func() time.Time { return now }
	return p, c, manifests, &now
}

// Once the applier has taken a stack's ConfigMap, the stack counts as applied;
// its Issuer and Certificate that cert-manager rejected (its CRDs or webhook
// weren't ready when the stack went in) don't come back by themselves. The
// cluster step doesn't pass over them: it says what it waits for, and puts the
// stack in front of k0s again so the applier tries the objects once more.
func TestTheClusterStepWaitsForAStacksRejectedCertificates(t *testing.T) {
	p, c, manifests, _ := certProbe(t, false)
	ctx := context.Background()
	r, err := p.Check(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r.Step != productup.StepCluster || !strings.Contains(r.Detail, "app-tls") || !strings.Contains(r.Detail, "certificates") || r.Failed {
		t.Fatalf("a stack whose certificates were rejected: %+v", r)
	}
	if _, err := os.Stat(filepath.Join(manifests, "app-tls", "tls.yaml")); err != nil {
		t.Fatalf("the stack wasn't put in front of k0s again: %v", err)
	}
	// cert-manager is ready now and the applier takes the stack again.
	c.certReady = true
	c.apply(t, p.Slot, "app-tls")
	r, err = p.Check(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r.Step != "phase:data" {
		t.Fatalf("with the certificates applied the phases go on: %+v", r)
	}
}

// The stack is put in front of k0s again at most once an interval, and only
// after the box's own wait, so a slow applier isn't asked over and over.
func TestTheClusterStepPlacesAStackAgainOnlyOncePerInterval(t *testing.T) {
	p, _, manifests, now := certProbe(t, false)
	ctx := context.Background()
	stack := filepath.Join(manifests, "app-tls")
	if _, err := p.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(stack); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(5 * time.Second)
	if _, err := p.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stack); err == nil {
		t.Fatal("the stack was placed again after 5 s")
	}
	*now = now.Add(30 * time.Second)
	if _, err := p.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stack); err != nil {
		t.Fatalf("the stack wasn't placed again after the interval: %v", err)
	}
}

// A rejection that doesn't clear fails the step with what the API server said,
// naming the stack and the object, instead of leaving the phase to time out.
func TestTheClusterStepFailsWithTheRejectionAfterTheRetries(t *testing.T) {
	p, _, _, now := certProbe(t, false)
	ctx := context.Background()
	var r productup.Result
	for i := 0; i < 12 && !r.Failed; i++ {
		var err error
		if r, err = p.Check(ctx); err != nil {
			t.Fatal(err)
		}
		*now = now.Add(30 * time.Second)
	}
	if !r.Failed || r.Step != productup.StepCluster {
		t.Fatalf("a permanent rejection: %+v", r)
	}
	for _, want := range []string{"app-tls", "Certificate", "app-identity", "webhook.cert-manager.io"} { // scrub:allow=fqdn -- a Kubernetes API group
		if !strings.Contains(r.Detail, want) {
			t.Fatalf("the failure %q doesn't say %q", r.Detail, want)
		}
	}
}

// Without cert-manager's CRDs there is nothing to put in front of k0s again:
// the step waits for them, and never takes the stack's files away or back.
func TestTheClusterStepWaitsForCertManagersCRDs(t *testing.T) {
	p, c, manifests, _ := certProbe(t, false)
	c.certCRD = false
	r, err := p.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Step != productup.StepCluster || !strings.Contains(r.Detail, "CRDs") || r.Failed {
		t.Fatalf("no CRDs yet: %+v", r)
	}
	if _, err := os.Stat(filepath.Join(manifests, "app-tls")); err == nil {
		t.Fatal("the stack was placed with no CRDs to take it")
	}
}

// k0s takes a stack's objects away when its directory goes, so putting the
// stack in front of it again replaces its files where they are and never
// removes the directory.
func TestPlacingAStackAgainReplacesItsFilesInPlace(t *testing.T) {
	p, _, manifests, _ := certProbe(t, false)
	dir := filepath.Join(manifests, "app-tls")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.yaml"), []byte("# the first placing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(dir, "keep.txt")
	if err := os.WriteFile(keep, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("the stack's directory was removed and made again: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "tls.yaml"))
	if !strings.Contains(string(b), "kind: Certificate") {
		t.Fatalf("the stack's file wasn't replaced: %q", b)
	}
}
