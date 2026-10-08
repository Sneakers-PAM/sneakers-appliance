// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package certstore

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// Check is one validation check.
type Check struct {
	// Name is key, usage, chain, names or validity.
	Name   string
	Passed bool
	Detail string
}

// ValidationError is a refused certificate: Err is the first failure's
// coded error, Checks every check run.
type ValidationError struct {
	Checks []Check
	Err    error
}

func (e *ValidationError) Error() string { return e.Err.Error() }
func (e *ValidationError) Unwrap() error { return e.Err }

// candidate is a certificate on its way into the store.
type candidate struct {
	leaf  *x509.Certificate
	chain []*x509.Certificate
	roots []*x509.Certificate
	// pub is the key the leaf must be for; keyDesc names it in errors.
	pub     crypto.PublicKey
	keyDesc string
}

type equaler interface{ Equal(crypto.PublicKey) bool }

// validate runs every check and returns the chain, leaf first and ending
// at its root. host and addrs are the box's management names; one must be
// covered.
func validate(c candidate, host string, addrs []string, now time.Time) ([]*x509.Certificate, []Check, error) {
	var checks []Check
	var first error
	fail := func(name string, err error) {
		checks = append(checks, Check{Name: name, Detail: sentence(err)})
		if first == nil {
			first = err
		}
	}
	pass := func(name, detail string) { checks = append(checks, Check{Name: name, Passed: true, Detail: detail}) }

	if e, ok := c.leaf.PublicKey.(equaler); !ok || !e.Equal(c.pub) {
		fail("key", codes.New(codes.TLSKeyMismatch, "this certificate is for a different key than %s", c.keyDesc))
	} else {
		pass("key", "matches "+c.keyDesc)
	}
	if err := checkKeyType(c.leaf.PublicKey); err != nil {
		fail("key", err)
	}

	switch {
	case c.leaf.IsCA:
		fail("usage", codes.New(codes.TLSUsage, "this is a CA certificate, not a server certificate"))
	case len(c.leaf.ExtKeyUsage) > 0 && !slices.Contains(c.leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) && !slices.Contains(c.leaf.ExtKeyUsage, x509.ExtKeyUsageAny):
		fail("usage", codes.New(codes.TLSUsage, "the certificate isn't for TLS servers (its extended key usage has no server authentication)"))
	default:
		pass("usage", "TLS server")
	}

	built, err := buildChain(c, now)
	if err != nil {
		fail("chain", err)
	} else {
		subjects := make([]string, 0, len(built))
		for _, b := range built {
			subjects = append(subjects, displayName(b))
		}
		pass("chain", strings.Join(subjects, " > "))
	}

	if covered := coveredNames(c.leaf, boxNames(host, addrs)); len(covered) == 0 {
		fail("names", namesError(c.leaf, host, addrs))
	} else {
		pass("names", "covers "+strings.Join(covered, ", "))
	}

	switch {
	case now.Before(c.leaf.NotBefore):
		fail("validity", codes.New(codes.TLSValidity, "the certificate is not valid until %s", c.leaf.NotBefore.UTC().Format(time.DateOnly)))
	case now.After(c.leaf.NotAfter):
		fail("validity", codes.New(codes.TLSValidity, "the certificate expired on %s (%s ago)", c.leaf.NotAfter.UTC().Format(time.DateOnly), days(now.Sub(c.leaf.NotAfter))))
	default:
		pass("validity", fmt.Sprintf("%s to %s (%s left)", c.leaf.NotBefore.UTC().Format(time.DateOnly), c.leaf.NotAfter.UTC().Format(time.DateOnly), days(c.leaf.NotAfter.Sub(now))))
	}

	if first != nil {
		return nil, checks, &ValidationError{Checks: checks, Err: first}
	}
	return built, checks, nil
}

// sentence is a coded error's text without its symbol and number.
func sentence(err error) string {
	d := codes.Describe(err)
	if _, after, ok := strings.Cut(d, "): "); ok {
		return after
	}
	return d
}

// buildChain verifies the leaf to a root: a self-signed certificate in
// the chain or the roots the admin uploaded. A leaf outside its validity
// is checked at its own start, so the chain check reports the chain and
// the validity check the dates.
func buildChain(c candidate, now time.Time) ([]*x509.Certificate, error) {
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	pool := slices.Concat(c.chain, c.roots)
	for _, x := range pool {
		if selfSigned(x) {
			roots.AddCert(x)
		} else {
			inter.AddCert(x)
		}
	}
	if selfSigned(c.leaf) {
		roots.AddCert(c.leaf)
	}
	at := now
	if now.Before(c.leaf.NotBefore) || now.After(c.leaf.NotAfter) {
		at = c.leaf.NotBefore.Add(time.Second)
	}
	chains, err := c.leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err == nil {
		return chains[0], nil
	}
	var ua x509.UnknownAuthorityError
	if errors.As(err, &ua) {
		stop := missingIssuer(c.leaf, pool)
		if stop == c.leaf {
			return nil, codes.New(codes.TLSChain, "the certificate's issuer %q isn't in the upload; add the chain (the intermediate certificates and the root)", issuerName(stop))
		}
		return nil, codes.New(codes.TLSChain, "the chain stops at %q: its issuer %q isn't in the upload; add that intermediate or root certificate, or upload the root on its own", displayName(stop), issuerName(stop))
	}
	var ci x509.CertificateInvalidError
	if errors.As(err, &ci) && ci.Cert != nil {
		return nil, codes.New(codes.TLSChain, "%q in the chain is invalid: %s", displayName(ci.Cert), ci.Error())
	}
	return nil, codes.New(codes.TLSChain, "the chain doesn't verify: %v", err)
}

// missingIssuer follows issuers from leaf through pool and returns the
// first certificate whose issuer isn't there.
func missingIssuer(leaf *x509.Certificate, pool []*x509.Certificate) *x509.Certificate {
	cur := leaf
	for range len(pool) + 1 {
		if selfSigned(cur) {
			return cur
		}
		var next *x509.Certificate
		for _, p := range pool {
			if bytes.Equal(p.RawSubject, cur.RawIssuer) && cur.CheckSignatureFrom(p) == nil {
				next = p
				break
			}
		}
		if next == nil {
			return cur
		}
		cur = next
	}
	return cur
}

func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(c) == nil
}

func displayName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return c.Subject.String()
}

func issuerName(c *x509.Certificate) string {
	if c.Issuer.CommonName != "" {
		return c.Issuer.CommonName
	}
	return c.Issuer.String()
}

// sans lists the certificate's DNS names, then its IP addresses.
func sans(c *x509.Certificate) []string {
	out := slices.Clone(c.DNSNames)
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

// namesError is the refusal of a certificate that covers none of the
// box's names: what the box checked and what the certificate covers. With
// no host name the box can only check its addresses, so it says how to
// set one.
func namesError(leaf *x509.Certificate, host string, addrs []string) error {
	has := "no names"
	if s := sans(leaf); len(s) > 0 {
		has = strings.Join(s, ", ")
	}
	if host == "" {
		checked := "no address"
		if len(addrs) > 0 {
			checked = strings.Join(addrs, ", ")
		}
		return codes.New(codes.TLSNoHostname, "this box has no host name yet, so the certificate is checked against %s only, and it covers %s; set the host name on Network (a fully qualified name such as appliance.example.org), then try again", checked, has)
	}
	return codes.New(codes.TLSNames, "the certificate covers %s, but none of the names this box checks: %s", has, strings.Join(boxNames(host, addrs), ", "))
}

func coveredNames(leaf *x509.Certificate, names []string) []string {
	var out []string
	for _, n := range names {
		if n != "" && leaf.VerifyHostname(n) == nil {
			out = append(out, n)
		}
	}
	return out
}

func days(d time.Duration) string {
	n := int(math.Floor(d.Hours() / 24))
	if n == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}
