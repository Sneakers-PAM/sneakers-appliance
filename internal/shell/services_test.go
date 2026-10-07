// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

// fakeLocal is osadmin's LocalService as the shell sees it.
type fakeLocal struct {
	osadminv1connect.UnimplementedLocalServiceHandler
	ua       string
	approved []*osadminv1.ApproveSignInRequest
	refuse   error
}

func (f *fakeLocal) DescribeSignIn(_ context.Context, r *connect.Request[osadminv1.DescribeSignInRequest]) (*connect.Response[osadminv1.DescribeSignInResponse], error) {
	if r.Msg.GetCode() != "ABCD-EFGH" {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("LOGIN_CODE (3201): unknown, used or expired sign-in code"))
	}
	return connect.NewResponse(&osadminv1.DescribeSignInResponse{SourceAddress: "192.0.2.50", UserAgent: f.ua}), nil
}

func (f *fakeLocal) ApproveSignIn(_ context.Context, r *connect.Request[osadminv1.ApproveSignInRequest]) (*connect.Response[osadminv1.ApproveSignInResponse], error) {
	if f.refuse != nil {
		return nil, f.refuse
	}
	f.approved = append(f.approved, r.Msg)
	return connect.NewResponse(&osadminv1.ApproveSignInResponse{}), nil
}

func services(t *testing.T, f *fakeLocal) *shell.Services {
	t.Helper()
	_, h := osadminv1connect.NewLocalServiceHandler(f)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &shell.Services{
		Session: shell.Session{Admin: "alice", KeyFingerprint: "SHA256:abc", Source: "192.0.2.60"},
		Local:   osadminv1connect.NewLocalServiceClient(http.DefaultClient, srv.URL),
	}
}

func runWith(t *testing.T, b shell.Backend, line, stdin string) (string, string, error) {
	t.Helper()
	var out, errb strings.Builder
	e := &shell.Env{Origin: shell.OriginSSH, Backend: b, In: strings.NewReader(stdin), Out: &out, Err: &errb}
	err := shell.Run(context.Background(), e, line)
	return out.String(), errb.String(), err
}

func TestLoginApprovesThroughOsadmin(t *testing.T) {
	f := &fakeLocal{ua: "Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0"}
	out, _, err := runWith(t, services(t, f), "login ABCD-EFGH", "y\n")
	if err != nil {
		t.Fatal(err)
	}
	want := "Sign in the browser at 192.0.2.50 (Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0) as alice? [y/N] "
	if !strings.Contains(out, want) {
		t.Fatalf("prompt %q", out)
	}
	if len(f.approved) != 1 {
		t.Fatalf("approvals %d", len(f.approved))
	}
	a := f.approved[0]
	if a.GetCode() != "ABCD-EFGH" || a.GetAdmin() != "alice" || a.GetKeyFingerprint() != "SHA256:abc" || a.GetSourceAddress() != "192.0.2.60" {
		t.Fatalf("%+v", a)
	}
	if !strings.Contains(out, "Signed in") {
		t.Fatalf("out %q", out)
	}
}

func TestLoginDefaultsToNo(t *testing.T) {
	for _, answer := range []string{"\n", "", "n\n", "yes please\n", "Y es\n"} {
		f := &fakeLocal{ua: "test-agent"}
		_, _, err := runWith(t, services(t, f), "login ABCD-EFGH", answer)
		if err != nil || len(f.approved) != 0 {
			t.Fatalf("answer %q: %v, %d approvals", answer, err, len(f.approved))
		}
	}
}

func TestLoginPromptNeutralisesTheUserAgent(t *testing.T) {
	f := &fakeLocal{ua: "evil\x1b[2J\x1b]0;title\x07\r\nSign in? [y/N] y" + strings.Repeat("A", 1000)}
	out, _, err := runWith(t, services(t, f), "login ABCD-EFGH", "n\n")
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(out, "\x1b\x07\r") || strings.Count(out, "\n") > 1 {
		t.Fatalf("control characters reached the terminal: %q", out)
	}
	if len(out) > 400 {
		t.Fatalf("the user agent isn't shortened: %d bytes", len(out))
	}
}

func TestLoginUnknownCode(t *testing.T) {
	_, stderr, err := runWith(t, services(t, &fakeLocal{}), "login ZZZZ-ZZZZ", "y\n")
	if err == nil || !strings.Contains(stderr, "LOGIN_CODE") {
		t.Fatalf("%v %q", err, stderr)
	}
}

func TestLoginRefusedByOsadmin(t *testing.T) {
	f := &fakeLocal{ua: "a", refuse: connect.NewError(connect.CodePermissionDenied, errors.New("ACCESS_FORBIDDEN (3009): that key isn't one of alice's keys"))}
	_, stderr, err := runWith(t, services(t, f), "login ABCD-EFGH", "y\n")
	if err == nil || !strings.Contains(stderr, "ACCESS_FORBIDDEN") {
		t.Fatalf("%v %q", err, stderr)
	}
}

func TestLoginOsadminDown(t *testing.T) {
	s := &shell.Services{Session: shell.Session{Admin: "alice", KeyFingerprint: "SHA256:abc"}, Local: osadminv1connect.NewLocalServiceClient(http.DefaultClient, "http://127.0.0.1:1")}
	_, stderr, err := runWith(t, s, "login ABCD-EFGH", "y\n")
	if !codes.Is(err, codes.NotAvailable) || !strings.Contains(stderr, "appliance admin (:8443) isn't answering") {
		t.Fatalf("%v %q", err, stderr)
	}
}

func TestLaterSpecCommandsAreNotAvailable(t *testing.T) {
	s := &shell.Services{}
	for _, line := range []string{"tls show", "backup list", "restore", "upgrade status", "mcp off", "resources", "logs export", "support-bundle"} {
		_, stderr, err := runWith(t, s, line, "")
		if !codes.Is(err, codes.NotAvailable) || !strings.Contains(stderr, "Not available in this release") {
			t.Errorf("%q: %v %q", line, err, stderr)
		}
	}
}

func TestAccessdCommandsSayServicesUnavailable(t *testing.T) {
	s := &shell.Services{}
	for _, line := range []string{"status", "keys list", "admins list", "network show", "elevation status"} {
		_, stderr, err := runWith(t, s, line, "")
		if !codes.Is(err, codes.NotAvailable) || !strings.Contains(stderr, "appliance services are unavailable") {
			t.Errorf("%q: %v %q", line, err, stderr)
		}
	}
}
