// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productsetup_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productsetup"
)

// fakeK0s writes a k0s that records its arguments and prints out.
func fakeK0s(t *testing.T, out string, exit int) (string, string) {
	t.Helper()
	dir := t.TempDir()
	args := filepath.Join(dir, "args")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + args + "\nprintf '%s' '" + out + "'\nexit " + string(rune('0'+exit)) + "\n"
	p := filepath.Join(dir, "k0s")
	if err := os.WriteFile(p, []byte(script), 0o700); err != nil { // #nosec G306 -- the test's fake k0s
		t.Fatal(err)
	}
	return p, args
}

// The probe asks the product's gateway, through the API server's service
// proxy, whether it still needs its first admin.
func TestTheProbeAsksTheGateway(t *testing.T) {
	k0s, args := fakeK0s(t, `{"needsSetup":true}`, 0)
	probe := productsetup.KubectlProbe(k0s, "/var/lib/k0s/pki/admin.conf")
	needs, err := probe(context.Background())
	if err != nil || !needs {
		t.Fatalf("needs %v %v", needs, err)
	}
	b, err := os.ReadFile(args) // #nosec G304 -- the test's own file
	if err != nil {
		t.Fatal(err)
	}
	want := "kubectl\n--kubeconfig\n/var/lib/k0s/pki/admin.conf\nget\n--raw\n/api/v1/namespaces/sneakers/services/sneakers-gateway:http/proxy/setup/state\n"
	if string(b) != want {
		t.Fatalf("args\n%s", b)
	}
	k0s, _ = fakeK0s(t, `{"needsSetup":false}`, 0)
	if needs, err := productsetup.KubectlProbe(k0s, "x")(context.Background()); err != nil || needs {
		t.Fatalf("set up: %v %v", needs, err)
	}
	k0s, _ = fakeK0s(t, `Error from server (ServiceUnavailable)`, 1)
	if _, err := productsetup.KubectlProbe(k0s, "x")(context.Background()); err == nil || !strings.Contains(err.Error(), "ServiceUnavailable") {
		t.Fatalf("a failing kubectl: %v", err)
	}
	k0s, _ = fakeK0s(t, `{}`, 0)
	if _, err := productsetup.KubectlProbe(k0s, "x")(context.Background()); err == nil {
		t.Fatal("an answer without needsSetup was taken")
	}
}
