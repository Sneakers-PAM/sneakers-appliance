// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// docs splits a rendered stack into its YAML documents by kind.
func docs(t *testing.T, b []byte) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	for {
		var d map[string]any
		if err := dec.Decode(&d); errors.Is(err, io.EOF) {
			return out
		} else if err != nil {
			t.Fatalf("the stack doesn't parse: %v\n%s", err, b)
		}
		md := d["metadata"].(map[string]any)
		out[d["kind"].(string)+"/"+md["name"].(string)] = d
	}
}

func dig(t *testing.T, m map[string]any, path ...string) any {
	t.Helper()
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("%v: %q isn't a map", path, p)
		}
		cur = mm[p]
	}
	return cur
}

func TestHTTP01StackNamesTheBoxAndTheEdgesPort80(t *testing.T) {
	b, err := Render(Config{Issuer: IssuerStaging, Email: "ops@example.org", Challenge: ChallengeHTTP01}, []string{"box.example.org"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	d := docs(t, b)
	iss := d["Issuer/"+IssuerName]
	if got := dig(t, iss, "spec", "acme", "server"); got != StagingDirectory {
		t.Fatalf("server %v", got)
	}
	if got := dig(t, iss, "metadata", "namespace"); got != Namespace {
		t.Fatalf("the issuer is in %v: the edge only watches %s", got, Namespace)
	}
	sol := dig(t, iss, "spec", "acme", "solvers").([]any)[0].(map[string]any)
	ing := dig(t, sol, "http01", "ingress").(map[string]any)
	if ing["ingressClassName"] != "traefik" {
		t.Fatalf("solver ingress %v", ing)
	}
	if got := dig(t, ing, "ingressTemplate", "metadata", "annotations", "traefik.ingress.kubernetes.io/router.entrypoints"); got != "web" {
		t.Fatalf("the solver must answer on port 80: %v", got)
	}
	cert := d["Certificate/"+CertName]
	if got := dig(t, cert, "spec", "secretName"); got != SecretName {
		t.Fatalf("secretName %v", got)
	}
	if names := dig(t, cert, "spec", "dnsNames").([]any); len(names) != 1 || names[0] != "box.example.org" {
		t.Fatalf("dnsNames %v", names)
	}
	if _, ok := d["NetworkPolicy/"+SolverPolicy]; !ok {
		t.Fatal("no policy lets the edge reach the solver pod")
	}
	if _, ok := d["Secret/"+DNSSecret]; ok {
		t.Fatal("an HTTP-01 stack carries no DNS token")
	}
}

func TestTheApplianceMayReadOnlyTheIssuedPairAndTheCertificate(t *testing.T) {
	b, err := Render(Config{Issuer: IssuerStaging, Email: "ops@example.org", Challenge: ChallengeHTTP01}, []string{"box.example.org"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	d := docs(t, b)
	rules := dig(t, d["Role/"+ReadRole], "rules").([]any)
	if len(rules) != 2 {
		t.Fatalf("rules %v", rules)
	}
	for _, r := range rules {
		rule := r.(map[string]any)
		if verbs := rule["verbs"].([]any); len(verbs) != 1 || verbs[0] != "get" {
			t.Fatalf("a read-only Role may only get: %v", rule)
		}
		if names := rule["resourceNames"].([]any); len(names) != 1 {
			t.Fatalf("each rule names its one object: %v", rule)
		}
	}
	subj := dig(t, d["RoleBinding/"+ReadRole], "subjects").([]any)[0].(map[string]any)
	if subj["name"] != productspec.ServiceAccount || subj["namespace"] != productspec.Namespace {
		t.Fatalf("the binding is for %v", subj)
	}
}

func TestDNS01StackCarriesTheTokenAndNoSolverPolicy(t *testing.T) {
	b, err := Render(Config{Issuer: IssuerProduction, Email: "ops@example.org", Challenge: ChallengeDNS01, DNSProvider: "cloudflare", DNSToken: "tok-1"}, []string{"box.example.org"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	d := docs(t, b)
	if got := dig(t, d["Issuer/"+IssuerName], "spec", "acme", "server"); got != ProductionDirectory {
		t.Fatalf("server %v", got)
	}
	sec := d["Secret/"+DNSSecret]
	if sec == nil || dig(t, sec, "stringData", "api-token") != "tok-1" {
		t.Fatalf("the token Secret: %v", sec)
	}
	sol := dig(t, d["Issuer/"+IssuerName], "spec", "acme", "solvers").([]any)[0].(map[string]any)
	if dig(t, sol, "dns01", "cloudflare", "apiTokenSecretRef", "name") != DNSSecret {
		t.Fatalf("solver %v", sol)
	}
	if _, ok := d["NetworkPolicy/"+SolverPolicy]; ok {
		t.Fatal("DNS-01 starts no solver pod, so it needs no policy")
	}
}

func TestACustomDirectoryCarriesItsExternalAccountBinding(t *testing.T) {
	b, err := Render(Config{Issuer: IssuerCustom, DirectoryURL: "https://ca.example.org/acme/directory", Email: "ops@example.org", Challenge: ChallengeHTTP01, EABKeyID: "kid-1", EABHMACKey: "aGVsbG8"}, []string{"box.example.org"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	d := docs(t, b)
	eab := dig(t, d["Issuer/"+IssuerName], "spec", "acme", "externalAccountBinding").(map[string]any)
	if eab["keyID"] != "kid-1" || dig(t, eab, "keySecretRef", "name") != EABSecret {
		t.Fatalf("eab %v", eab)
	}
	if dig(t, d["Secret/"+EABSecret], "stringData", "secret") != "aGVsbG8" {
		t.Fatal("the EAB key isn't in its Secret")
	}
}

func TestRenewSerialChangesTheCertificateSpecAndNothingElse(t *testing.T) {
	c := Config{Issuer: IssuerStaging, Email: "ops@example.org", Challenge: ChallengeHTTP01}
	a, _ := Render(c, []string{"box.example.org"}, 0)
	b, _ := Render(c, []string{"box.example.org"}, 2)
	if bytes.Equal(a, b) {
		t.Fatal("renewing must change what k0s applies, or cert-manager sees nothing to do")
	}
	ou := dig(t, docs(t, b)["Certificate/"+CertName], "spec", "subject", "organizationalUnits").([]any)
	if len(ou) != 1 || ou[0] != "renewal-2" {
		t.Fatalf("subject %v", ou)
	}
	if strings.Contains(string(a), "renewal-") {
		t.Fatal("a first issue carries no renewal marker")
	}
}

func TestValidateRefusesWhatTheBoxCantIssue(t *testing.T) {
	ok := Config{Issuer: IssuerStaging, Email: "ops@example.org", Challenge: ChallengeHTTP01}
	for name, tc := range map[string]struct {
		mut   func(*Config)
		names []string
	}{
		"no issuer":            {func(c *Config) { c.Issuer = "" }, []string{"box.example.org"}},
		"custom without url":   {func(c *Config) { c.Issuer = IssuerCustom }, []string{"box.example.org"}},
		"custom url not https": {func(c *Config) { c.Issuer = IssuerCustom; c.DirectoryURL = "http://ca.example.org/dir" }, []string{"box.example.org"}},
		"no email":             {func(c *Config) { c.Email = "" }, []string{"box.example.org"}},
		"no challenge":         {func(c *Config) { c.Challenge = "" }, []string{"box.example.org"}},
		"dns01 no provider":    {func(c *Config) { c.Challenge = ChallengeDNS01 }, []string{"box.example.org"}},
		"dns01 other provider": {func(c *Config) { c.Challenge = ChallengeDNS01; c.DNSProvider = "route53"; c.DNSToken = "t" }, []string{"box.example.org"}},
		"dns01 no token":       {func(c *Config) { c.Challenge = ChallengeDNS01; c.DNSProvider = "cloudflare" }, []string{"box.example.org"}},
		"eab key id only":      {func(c *Config) { c.EABKeyID = "k" }, []string{"box.example.org"}},
		"no names":             {func(c *Config) {}, nil},
		"an address":           {func(c *Config) {}, []string{"192.0.2.10"}},
		"a bare label":         {func(c *Config) {}, []string{"box"}},
		"http01 wildcard":      {func(c *Config) {}, []string{"*.example.org"}},
	} {
		c := ok
		tc.mut(&c)
		_, err := Render(c, tc.names, 0)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !codes.Is(err, codes.TLSInvalid) && !codes.Is(err, codes.TLSNoHostname) {
			t.Errorf("%s: %v isn't a coded refusal", name, err)
		}
	}
	if _, err := Render(ok, []string{"box.example.org"}, 0); err != nil {
		t.Fatalf("the good config: %v", err)
	}
}
