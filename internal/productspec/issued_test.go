// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productspec

import (
	"strings"
	"testing"
)

// A product names the Secrets something else issues (cert-manager's
// certificates for the services), which its workloads read and the box never
// makes.
func TestAProductDeclaresTheSecretsSomethingElseIssues(t *testing.T) {
	s, err := Parse([]byte("format: 2\nissued_secrets:\n  - secret: sneakers/sneakers-audit-tls\n    keys: [tls.crt, tls.key, ca.crt]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.IssuedSecrets) != 1 {
		t.Fatalf("issued secrets %+v", s.IssuedSecrets)
	}
	is := s.IssuedSecrets[0]
	if is.Namespace() != "sneakers" || is.SecretName() != "sneakers-audit-tls" || strings.Join(is.Keys, ",") != "tls.crt,tls.key,ca.crt" {
		t.Fatalf("%+v", is)
	}
}

func TestABadIssuedSecretsSectionIsRefused(t *testing.T) {
	for name, y := range map[string]string{
		"no namespace":      "format: 2\nissued_secrets:\n  - {secret: audit-tls, keys: [tls.crt]}\n",
		"no keys":           "format: 2\nissued_secrets:\n  - {secret: sneakers/audit-tls, keys: []}\n",
		"a bad key":         "format: 2\nissued_secrets:\n  - {secret: sneakers/audit-tls, keys: [\"a b\"]}\n",
		"a repeated key":    "format: 2\nissued_secrets:\n  - {secret: sneakers/audit-tls, keys: [tls.crt, tls.crt]}\n",
		"declared twice":    "format: 2\nissued_secrets:\n  - {secret: sneakers/audit-tls, keys: [tls.crt]}\n  - {secret: sneakers/audit-tls, keys: [tls.key]}\n",
		"the appliance's":   "format: 2\nissued_secrets:\n  - {secret: sneakers-appliance/audit-tls, keys: [tls.crt]}\n",
		"also a box secret": "format: 2\nbox_secrets:\n  - secret: sneakers/audit-tls\n    keys: [{key: tls.crt, generate: password}]\nissued_secrets:\n  - {secret: sneakers/audit-tls, keys: [tls.crt]}\n",
		"an unknown key":    "format: 2\nissued_secrets:\n  - {secret: sneakers/audit-tls, keys: [tls.crt], generate: password}\n",
	} {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// A base before rc.8 refuses a product.yaml with the section, so a bundle
// that has one is never sealed for it.
func TestIssuedSecretsNeedTheBaseThatReadsThem(t *testing.T) {
	s, err := Parse([]byte("format: 2\ntelemetry: {}\nissued_secrets:\n  - {secret: sneakers/audit-tls, keys: [tls.crt]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	floor, why := s.BaseFloor()
	if floor != IssuedSecretsMinBase || !strings.Contains(why, "issue") {
		t.Fatalf("the floor: %q %q", floor, why)
	}
}
