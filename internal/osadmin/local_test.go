// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/initapi"
)

// The local socket reads the caller's uid: this test process is neither
// root nor an admin uid, so it may describe a code but not approve one.
func TestLocalSocketUsesThePeerUID(t *testing.T) {
	b := newBox(t, false)
	sock := filepath.Join(t.TempDir(), "osadmin.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: b.srv.LocalHandler(), ConnContext: initapi.PeerContext, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(initapi.PeerListener(ln, func(uint32) bool { return true }, t.Logf)) }()
	t.Cleanup(func() { _ = srv.Close() })
	hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	lc := osadminv1connect.NewLocalServiceClient(hc, "http://osadmin.sock")
	ctx := context.Background()
	begin, err := osadminv1connect.NewSignInServiceClient(b.browser().hc, b.ts.URL).BeginSignIn(ctx, connect.NewRequest(&osadminv1.BeginSignInRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	d, err := lc.DescribeSignIn(ctx, connect.NewRequest(&osadminv1.DescribeSignInRequest{Code: begin.Msg.GetCode()}))
	if err != nil || d.Msg.GetUserAgent() != "TestBrowser/1.0" {
		t.Fatalf("%v %v", d, err)
	}
	_, err = lc.ApproveSignIn(ctx, connect.NewRequest(&osadminv1.ApproveSignInRequest{Code: begin.Msg.GetCode(), Admin: "alice", KeyFingerprint: b.keys["alice"].fp}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
}
