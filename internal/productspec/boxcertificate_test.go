// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productspec

import (
	"slices"
	"strings"
	"testing"
)

const certYAML = `format: 2
box_secrets:
  - secret: app/app-tls
    certificate:
      common_name: db.app.svc
      dns_names: [db, "*.db-headless.app.svc"]
`

func TestABoxCertificateIsReadAsDeclared(t *testing.T) {
	s, err := Parse([]byte(certYAML))
	if err != nil {
		t.Fatal(err)
	}
	c := s.BoxSecrets[0].Certificate
	if c == nil || c.CommonName != "db.app.svc" || !slices.Equal(c.DNSNames, []string{"db", "*.db-headless.app.svc"}) {
		t.Fatalf("%+v", c)
	}
	if got := s.BoxSecrets[0].KeyNames(); !slices.Equal(got, []string{"tls.crt", "tls.key", "ca.crt"}) {
		t.Fatalf("keys: %v", got)
	}
}

func TestABadBoxCertificateIsRefused(t *testing.T) {
	for name, y := range map[string]string{
		"with keys":       strings.Replace(certYAML, "    certificate:", "    keys:\n      - {key: a, generate: token}\n    certificate:", 1),
		"no common name":  strings.Replace(certYAML, "common_name: db.app.svc", "common_name: ''", 1),
		"no names":        strings.Replace(certYAML, `dns_names: [db, "*.db-headless.app.svc"]`, "dns_names: []", 1),
		"a bad name":      strings.Replace(certYAML, "[db,", `["a b",`, 1),
		"a deep wildcard": strings.Replace(certYAML, "*.db-headless", "a.*.db-headless", 1),
	} {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
}
