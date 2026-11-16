// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package acme writes the k0s stack that has the product bundle's
// cert-manager issue the box's certificate: an Issuer for the ACME
// directory, the Certificate for the box's host name, the Secrets the
// challenge needs and, for HTTP-01, the NetworkPolicy that lets the edge
// reach the solver pod. cert-manager keeps the issued pair in the Secret
// SecretName; internal/certstore reads it from there and assigns it through
// the same check and rollback as an uploaded certificate (sneakers-appliance#531).
//
// Everything is in the product namespace, which Traefik's ingress provider
// already watches, so the solver's Ingress is seen without widening the
// edge.
package acme

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// Where the stack lives and what it is called.
const (
	// Stack is the k0s stack the manifests go in (k0s's manifests/<Stack>).
	Stack = "box-acme"
	// Namespace is the product's namespace, the one the edge watches.
	Namespace = "sneakers"
	// IssuerName and CertName name the Issuer and the Certificate.
	IssuerName = "box-acme"
	CertName   = "box-acme"
	// SecretName is the Secret cert-manager writes the issued pair to
	// (tls.crt, tls.key).
	SecretName = "box-acme-tls" // #nosec G101 -- the name of a Secret, not a credential
	// AccountSecret keeps the ACME account key cert-manager makes.
	AccountSecret = "box-acme-account" // #nosec G101 -- the name of a Secret, not a credential
	// DNSSecret and EABSecret carry the write-only settings.
	DNSSecret = "box-acme-dns" // #nosec G101 -- the name of a Secret, not a credential
	EABSecret = "box-acme-eab" // #nosec G101 -- the name of a Secret, not a credential
	// ReadRole is the Role and RoleBinding that let the appliance's service
	// account (internal/kubeapi) read the issued pair and the Certificate,
	// and nothing else.
	ReadRole = "box-acme-read"
	// SolverPolicy lets the edge reach the HTTP-01 solver pod.
	SolverPolicy = "box-acme-solver"
)

// The directories of the two public issuers.
const (
	StagingDirectory    = "https://acme-staging-v02.api.letsencrypt.org/directory" // scrub:allow=fqdn -- the public Let's Encrypt directory
	ProductionDirectory = "https://acme-v02.api.letsencrypt.org/directory"         // scrub:allow=fqdn -- the public Let's Encrypt directory
)

// Issuers, challenges and the one DNS provider.
const (
	IssuerStaging    = "letsencrypt-staging"
	IssuerProduction = "letsencrypt-production"
	IssuerCustom     = "custom"

	ChallengeHTTP01 = "http-01"
	ChallengeDNS01  = "dns-01"

	ProviderCloudflare = "cloudflare"
)

// Config is what an owner chooses.
type Config struct {
	Issuer       string
	DirectoryURL string
	Email        string
	Challenge    string
	DNSProvider  string
	// DNSToken is the DNS provider's API token, carried into the stack's
	// Secret (the stack is root-only on the state volume, like box-tls).
	DNSToken string
	// EABKeyID and EABHMACKey are External Account Binding, for a custom
	// directory that needs it.
	EABKeyID, EABHMACKey string
}

// Directory is the ACME directory URL c names.
func (c Config) Directory() string {
	switch c.Issuer {
	case IssuerStaging:
		return StagingDirectory
	case IssuerProduction:
		return ProductionDirectory
	}
	return c.DirectoryURL
}

func invalid(format string, args ...any) error {
	return codes.New(codes.TLSInvalid, format, args...)
}

// Validate refuses a Config and names the box can't have issued.
func Validate(c Config, names []string) error {
	switch c.Issuer {
	case IssuerStaging, IssuerProduction:
	case IssuerCustom:
		u, err := url.Parse(c.DirectoryURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return invalid("acme: a custom issuer needs an https directory URL")
		}
	default:
		return invalid("acme: choose an issuer: Let's Encrypt staging, production or a custom directory")
	}
	if !strings.Contains(c.Email, "@") || strings.ContainsAny(c.Email, " \t\r\n") {
		return invalid("acme: the CA needs an email address for the account")
	}
	if (c.EABKeyID == "") != (c.EABHMACKey == "") {
		return invalid("acme: External Account Binding needs both the key id and the HMAC key")
	}
	switch c.Challenge {
	case ChallengeHTTP01:
	case ChallengeDNS01:
		if c.DNSProvider != ProviderCloudflare {
			return invalid("acme: DNS-01 supports the %s provider only", ProviderCloudflare)
		}
		if c.DNSToken == "" {
			return invalid("acme: DNS-01 needs the provider's API token")
		}
	default:
		return invalid("acme: choose a challenge: HTTP-01 or DNS-01")
	}
	if len(names) == 0 {
		return codes.New(codes.TLSNoHostname, "acme: the box has no host name to issue a certificate for; set it on Network")
	}
	for _, n := range names {
		if net.ParseIP(n) != nil {
			return invalid("acme: a CA doesn't issue for the address %s; set the host name on Network", n)
		}
		if !strings.Contains(strings.TrimPrefix(n, "*."), ".") {
			return invalid("acme: %q isn't a fully qualified name", n)
		}
		if strings.HasPrefix(n, "*.") && c.Challenge != ChallengeDNS01 {
			return invalid("acme: a wildcard name (%s) needs the DNS-01 challenge", n)
		}
	}
	return nil
}

// Render is the stack for c and names. renewal is the renew-now count: a
// value above 0 goes into the Certificate's subject, which makes
// cert-manager issue again, and a first issue carries no marker.
func Render(c Config, names []string, renewal int) ([]byte, error) {
	if err := Validate(c, names); err != nil {
		return nil, err
	}
	var docs []map[string]any
	meta := func(name string) map[string]any {
		return map[string]any{"name": name, "namespace": Namespace}
	}
	solver := map[string]any{}
	if c.Challenge == ChallengeDNS01 {
		docs = append(docs, map[string]any{
			"apiVersion": "v1", "kind": "Secret", "metadata": meta(DNSSecret),
			"type": "Opaque", "stringData": map[string]any{"api-token": c.DNSToken},
		})
		solver["dns01"] = map[string]any{"cloudflare": map[string]any{
			"apiTokenSecretRef": map[string]any{"name": DNSSecret, "key": "api-token"},
		}}
	} else {
		// The edge's port 80 answers the challenge: its Ingress provider
		// reads this namespace, and the entry point is named so Traefik
		// binds the solver there and not to 443's gate.
		solver["http01"] = map[string]any{"ingress": map[string]any{
			"ingressClassName": "traefik",
			"ingressTemplate": map[string]any{"metadata": map[string]any{"annotations": map[string]any{
				"traefik.ingress.kubernetes.io/router.entrypoints": "web",
			}}},
		}}
		docs = append(docs, map[string]any{
			"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": meta(SolverPolicy),
			"spec": map[string]any{
				"podSelector": map[string]any{"matchLabels": map[string]any{"acme.cert-manager.io/http01-solver": "true"}}, // scrub:allow=fqdn -- a Kubernetes API group
				"policyTypes": []any{"Ingress"},
				"ingress":     []any{map[string]any{"ports": []any{map[string]any{"protocol": "TCP", "port": 8089}}}},
			},
		})
	}
	acmeSpec := map[string]any{
		"server":              c.Directory(),
		"email":               c.Email,
		"privateKeySecretRef": map[string]any{"name": AccountSecret},
		"solvers":             []any{solver},
	}
	if c.EABKeyID != "" {
		docs = append(docs, map[string]any{
			"apiVersion": "v1", "kind": "Secret", "metadata": meta(EABSecret),
			"type": "Opaque", "stringData": map[string]any{"secret": c.EABHMACKey},
		})
		acmeSpec["externalAccountBinding"] = map[string]any{
			"keyID":        c.EABKeyID,
			"keySecretRef": map[string]any{"name": EABSecret, "key": "secret"},
		}
	}
	docs = append(docs, map[string]any{
		"apiVersion": "cert-manager.io/v1", "kind": "Issuer", "metadata": meta(IssuerName), // scrub:allow=fqdn -- a Kubernetes API group
		"spec": map[string]any{"acme": acmeSpec},
	})
	certSpec := map[string]any{
		"secretName": SecretName,
		"issuerRef":  map[string]any{"name": IssuerName, "kind": "Issuer", "group": "cert-manager.io"}, // scrub:allow=fqdn -- a Kubernetes API group
		"dnsNames":   toAny(names),
		"privateKey": map[string]any{"algorithm": "ECDSA", "size": 256, "rotationPolicy": "Always"},
		"usages":     []any{"digital signature", "key encipherment", "server auth"},
	}
	if renewal > 0 {
		certSpec["subject"] = map[string]any{"organizationalUnits": []any{fmt.Sprintf("renewal-%d", renewal)}}
	}
	docs = append(docs, map[string]any{
		"apiVersion": "cert-manager.io/v1", "kind": "Certificate", "metadata": meta(CertName), "spec": certSpec, // scrub:allow=fqdn -- a Kubernetes API group
	})

	docs = append(docs,
		map[string]any{
			"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": meta(ReadRole),
			"rules": []any{
				map[string]any{"apiGroups": []any{""}, "resources": []any{"secrets"}, "resourceNames": []any{SecretName}, "verbs": []any{"get"}},
				map[string]any{"apiGroups": []any{"cert-manager.io"}, "resources": []any{"certificates"}, "resourceNames": []any{CertName}, "verbs": []any{"get"}}, // scrub:allow=fqdn -- a Kubernetes API group
			},
		},
		map[string]any{
			"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": meta(ReadRole),
			"roleRef":  map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": ReadRole},
			"subjects": []any{map[string]any{"kind": "ServiceAccount", "name": productspec.ServiceAccount, "namespace": productspec.Namespace}},
		},
	)

	var out bytes.Buffer
	for i, d := range docs {
		b, err := yaml.Marshal(d)
		if err != nil {
			return nil, fmt.Errorf("acme: render: %w", err)
		}
		if i > 0 {
			out.WriteString("---\n")
		}
		out.Write(b)
	}
	return out.Bytes(), nil
}

func toAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}
