// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

type setupTokenAccessd struct {
	fakeAccessd
	answer *osadminv1.GetProductSetupTokenResponse
	calls  int
}

func (f *setupTokenAccessd) GetProductSetupToken(_ context.Context, r *connect.Request[accessv1.GetProductSetupTokenRequest]) (*connect.Response[accessv1.GetProductSetupTokenResponse], error) {
	f.saw(r.Header())
	f.calls++
	return connect.NewResponse(&accessv1.GetProductSetupTokenResponse{Setup: f.answer}), nil
}

// "sneakers setup-token" sits in the product's group on SSH and asks
// accessd each time: the token and the link while the product has no
// first admin, and only "already set up" after.
func TestSneakersSetupToken(t *testing.T) {
	if !slices.Contains(shell.NamesFor(shell.OriginSSH, sneakers), "sneakers setup-token") {
		t.Fatalf("SSH names %v", shell.NamesFor(shell.OriginSSH, sneakers))
	}
	f := &setupTokenAccessd{answer: &osadminv1.GetProductSetupTokenResponse{Product: "Sneakers", Token: "stp_abcdefghijklmnopqrstuvwxyz234567", SetupUrl: "https://box1.sneakers.example.org/admin/setup"}}
	s := setupTokenServer(t, f)
	run := func(line string) (string, error) {
		var out, errb bytes.Buffer
		e := &shell.Env{Origin: shell.OriginSSH, Backend: s, In: strings.NewReader(""), Out: &out, Err: &errb, Product: sneakers}
		err := shell.Run(context.Background(), e, line)
		return out.String() + errb.String(), err
	}
	out, err := run("sneakers setup-token")
	if err != nil || !strings.Contains(out, "stp_abcdefghijklmnopqrstuvwxyz234567") || !strings.Contains(out, "https://box1.sneakers.example.org/admin/setup") {
		t.Fatalf("before setup: %v\n%s", err, out)
	}
	f.answer = &osadminv1.GetProductSetupTokenResponse{Product: "Sneakers", SetUp: true, SetupUrl: "https://box1.sneakers.example.org/admin/setup"}
	out, err = run("sneakers setup-token")
	if err != nil || !strings.Contains(out, "Sneakers is already set up") || strings.Contains(out, "stp_") || strings.Contains(out, "https://") {
		t.Fatalf("after setup: %v\n%s", err, out)
	}
	if f.calls != 2 {
		t.Fatalf("accessd was asked %d times", f.calls)
	}
}

func setupTokenServer(t *testing.T, f *setupTokenAccessd) *shell.Services {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(accessv1connect.NewAccessServiceHandler(f))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	s := &shell.Services{Session: shell.Session{Admin: "alice", KeyFingerprint: "SHA256:abc", Source: "192.0.2.60"}}
	s.UseAccessd(http.DefaultClient, srv.URL)
	return s
}
