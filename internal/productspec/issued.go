// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productspec

import "strings"

// IssuedSecret is a Secret something other than the box makes and fills,
// which the product's workloads read: cert-manager's certificates for the
// services (tls.crt, tls.key, ca.crt). The box never makes or reads its
// values; the render accepts a workload that reads it, key and all, and the
// bundle carries no value for it.
type IssuedSecret struct {
	// Secret is "<namespace>/<name>".
	Secret string `yaml:"secret"`
	// Keys are the data keys the issuer writes.
	Keys []string `yaml:"keys"`
}

// Namespace is the Secret's namespace.
func (s IssuedSecret) Namespace() string { ns, _, _ := strings.Cut(s.Secret, "/"); return ns }

// SecretName is the Secret's name.
func (s IssuedSecret) SecretName() string { _, n, _ := strings.Cut(s.Secret, "/"); return n }

// IssuedSecretsMinBase is the first base release that reads a product.yaml's
// issued_secrets section; an older base refuses the whole product.yaml.
const IssuedSecretsMinBase = "0.1.0-rc.8" // #nosec G101 -- a release version, not a credential

func (s Spec) checkIssuedSecrets() error {
	box := map[string]bool{}
	for _, b := range s.BoxSecrets {
		box[b.Secret] = true
	}
	seen := map[string]bool{}
	for i, is := range s.IssuedSecrets {
		ns, name, ok := strings.Cut(is.Secret, "/")
		if !ok || !dnsRE.MatchString(ns) || !secretRE.MatchString(name) {
			return bad("issued_secrets[%d]: the secret %q isn't <namespace>/<name>", i, is.Secret)
		}
		if ns == Namespace {
			return bad("issued_secrets[%d]: %s is the appliance's own namespace", i, ns)
		}
		if seen[is.Secret] {
			return bad("issued_secrets[%d]: %s is declared twice", i, is.Secret)
		}
		seen[is.Secret] = true
		if box[is.Secret] {
			return bad("issued_secrets[%d]: %s is also a box secret: the box makes it, or something else issues it, not both", i, is.Secret)
		}
		if len(is.Keys) == 0 {
			return bad("issued_secrets[%d]: %s has no keys", i, is.Secret)
		}
		keys := map[string]bool{}
		for j, k := range is.Keys {
			if !keyRE.MatchString(k) || keys[k] {
				return bad("issued_secrets[%d].keys[%d]: %q isn't a Secret data key, or is declared twice", i, j, k)
			}
			keys[k] = true
		}
	}
	return nil
}
