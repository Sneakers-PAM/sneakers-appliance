// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

func edLine(t *testing.T, comment string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))) + " " + comment
}

// A code forge's published keys: each line that passes the login key rules
// comes back to be confirmed; the rest are listed as refused.
func TestFetchKeys(t *testing.T) {
	a, b := edLine(t, "laptop"), edLine(t, "desk")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, "%s\n# a comment\n\nssh-dss AAAAB3NzaC1kc3MAAACBAP old\n%s\n", a, b)
	}))
	defer srv.Close()
	got, err := access.FetchKeys(context.Background(), srv.Client(), srv.URL+"/alice.keys")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Keys) != 2 || got.Keys[0].Comment != "laptop" || got.Keys[1].Comment != "desk" || len(got.Refused) != 1 {
		t.Fatalf("%+v", got)
	}
}

// Only https, and never a redirect down to http.
func TestFetchKeysRefusesHTTP(t *testing.T) {
	_, err := access.FetchKeys(context.Background(), http.DefaultClient, "http://192.0.2.1/keys")
	if !codes.Is(err, codes.AccessKeyType) {
		t.Fatalf("plain http: %v", err)
	}
	srv := httptest.NewTLSServer(http.RedirectHandler("http://192.0.2.1/keys", http.StatusFound))
	defer srv.Close()
	_, err = access.FetchKeys(context.Background(), srv.Client(), srv.URL)
	if !codes.Is(err, codes.AccessKeyType) {
		t.Fatalf("a redirect to http: %v", err)
	}
}

func TestFetchKeysWithNoKeys(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, "<html>not found</html>") }))
	defer srv.Close()
	if _, err := access.FetchKeys(context.Background(), srv.Client(), srv.URL); !codes.Is(err, codes.AccessKeyType) {
		t.Fatalf("err = %v", err)
	}
}
