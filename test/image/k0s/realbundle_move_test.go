// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

package k0s_test

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/test/image/harness"
)

// TestTheRealBundleMovesTheDatabase is the data move on a real box: a box on
// the base under test running rc.6, the last product on the old database
// cluster, takes the product under test through the normal update path.
// Every row has to come out of the update on the new cluster, with the move
// settled, and stay there through a power loss.
func TestTheRealBundleMovesTheDatabase(t *testing.T) {
	e := needReal(t)
	rc6, image := os.Getenv("SNEAKERS_REAL_RC6"), os.Getenv("SNEAKERS_REAL_NEW_IMAGE")
	if rc6 == "" || image == "" {
		t.Skip("SNEAKERS_REAL_RC6 and SNEAKERS_REAL_NEW_IMAGE name rc.6's bundle and the base under test")
	}
	harness.Need(t, nil, rc6, image)
	b := newRealBoxFrom(t, e, image, e.newVersion, 0)
	vOld, vNext := productVersion(rc6), productVersion(e.next)

	b.apply(rc6, "UPDATE_TARGET_PRODUCT")
	base := b.mustRun(vOld, "the install of "+vOld, realRows{}, true, false).rows
	if p := canaryProblems(base); len(p) > 0 {
		t.Fatalf("the rows weren't written: %v", p)
	}
	// The product's own first records go into the audit trail the move's
	// check reads: one carries no attributes (stored as JSON null).
	b.productAdmin()
	// The MCP is on, as it is on a box that has been using it: its own
	// stack and Certificate come with the update too.
	b.mcpOn()
	on := func(version, when string) {
		t.Helper()
		l := lastLine(b.vm.Console(), "realci: database running version="+version+" ")
		if !strings.Contains(l, "on=sneakers-pgha-0") || !strings.Contains(l, "move=done") {
			t.Fatalf("%s: the box isn't settled on the new cluster: %q", when, l)
		}
	}
	// The update brings cert-manager and the services' certificates to a box
	// that had none: every one of them has to be there when it is up, however
	// the applier's first pass went (#642).
	certs := func(version, when string) {
		t.Helper()
		l := lastLine(b.vm.Console(), "realci: certs running version="+version+" ")
		var issuers, certificates, secrets int
		for _, f := range strings.Fields(l) {
			k, v, ok := strings.Cut(f, "=")
			n, _ := strconv.Atoi(v)
			switch {
			case ok && k == "issuers":
				issuers = n
			case ok && k == "certificates":
				certificates = n
			case ok && k == "secrets":
				secrets = n
			}
		}
		if issuers < 2 || certificates < 9 || secrets < 9 {
			t.Fatalf("%s: the product's certificates aren't all there (want at least 2 issuers, 9 certificates, 9 tls secrets): %q", when, l)
		}
	}
	if l := lastLine(b.vm.Console(), "realci: database running version="+vOld+" "); !strings.Contains(l, "on=sneakers-postgres-0") {
		t.Fatalf("rc.6 isn't on the old cluster: %q", l)
	}

	start := time.Now()
	b.apply(e.next, "UPDATE_TARGET_PRODUCT")
	b.mustRun(vNext, "the move ("+vOld+" to "+vNext+")", base, true, false)
	t.Logf("the update with its move took %s", time.Since(start).Round(time.Second))
	on(vNext, "the move")

	certs(vNext, "the move")

	b.powerLoss()
	b.mustRun(vNext, "after a power loss", base, true, false)
	on(vNext, "after a power loss")
	certs(vNext, "after a power loss")
}
