// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package edgefall_test

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxstate"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/edgefall"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
)

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func claimer(t *testing.T, https, plain string, cert func() (tls.Certificate, error)) *edgefall.Claimer {
	t.Helper()
	c := edgefall.NewClaimer(edgefall.ClaimOptions{
		HTTPS: https, HTTP: plain, Cert: cert,
		Handler: edgefall.NewServer(func() boxstate.State { return boxstate.Rebooting }),
	})
	t.Cleanup(c.Close)
	return c
}

func boxCert(t *testing.T) func() (tls.Certificate, error) {
	t.Helper()
	l := testpki.NewTLSCA(t).Issue(t, testpki.LeafOptions{Names: []string{"box.example.org", "127.0.0.1"}})
	return func() (tls.Certificate, error) { return tls.X509KeyPair(l.PEM, l.KeyPEM) }
}

func httpsGet(t *testing.T, addr string) (int, string, error) {
	t.Helper()
	hc := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // #nosec G402 -- the test's self-signed box certificate
	res, err := hc.Get("https://" + addr + "/")
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b), nil
}

// Claimed, edgefall answers 443 with the page over TLS and 80 with the
// redirect; released, it lets both go so Traefik can bind them.
func TestAClaimServesThePageAndAReleaseLetsThePortsGo(t *testing.T) {
	https, plain := freePort(t), freePort(t)
	c := claimer(t, https, plain, boxCert(t))
	c.Want(true)
	if !c.Held() {
		t.Fatal("not held")
	}
	code, body, err := httpsGet(t, https)
	if err != nil || code != http.StatusServiceUnavailable || !strings.Contains(body, "Sneakers-PAM is rebooting") {
		t.Fatalf("%d %v", code, err)
	}
	c.Want(false)
	if c.Held() {
		t.Fatal("still held")
	}
	for _, a := range []string{https, plain} {
		ln, err := net.Listen("tcp", a)
		if err != nil {
			t.Fatalf("%s isn't free after the release: %v", a, err)
		}
		_ = ln.Close()
	}
}

// While Traefik still holds 443 the claim waits, and takes the ports on
// the first try after Traefik lets go; it never holds one without the
// other.
func TestAClaimWaitsForTraefikToLetGo(t *testing.T) {
	https, plain := freePort(t), freePort(t)
	traefik, err := net.Listen("tcp", https)
	if err != nil {
		t.Fatal(err)
	}
	c := claimer(t, https, plain, boxCert(t))
	c.Want(true)
	if c.Held() {
		t.Fatal("held while Traefik has 443")
	}
	if ln, err := net.Listen("tcp", plain); err != nil {
		t.Fatalf("80 was kept without 443: %v", err)
	} else {
		_ = ln.Close()
	}
	_ = traefik.Close()
	c.Want(true)
	if !c.Held() {
		t.Fatal("not held once Traefik let go")
	}
}

// Without the box's certificate edgefall claims nothing: a 443 with
// another certificate would be worse than none.
func TestNoCertificateNoClaim(t *testing.T) {
	c := claimer(t, freePort(t), freePort(t), func() (tls.Certificate, error) { return tls.Certificate{}, errors.New("no tls.crt") })
	c.Want(true)
	if c.Held() {
		t.Fatal("held without a certificate")
	}
}
