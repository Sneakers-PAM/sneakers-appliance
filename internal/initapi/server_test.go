// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package initapi_test

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/initapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/phase"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/services"
)

func client(sock string) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
}

func serve(t *testing.T, allow func(uint32) bool) (string, *http.Client) {
	t.Helper()
	tbl := services.Table{"sleeper": {Name: "sleeper", Exec: "/bin/sleep", Args: []string{"30"}, Phases: []phase.Phase{phase.Normal}, Restart: services.RestartNever, Start: services.StartOnDemand}}
	sup := services.NewSupervisor(services.ExecRunner{}, tbl, services.Options{StopTimeout: time.Second})
	_ = sup.EnterPhase(context.Background(), phase.Normal)
	sock := filepath.Join(t.TempDir(), "init.sock")
	srv, err := initapi.Listen(sock, initapi.Options{Allow: allow, Supervisor: sup})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Stop)
	st, err := os.Stat(sock)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v %v", st.Mode(), err)
	}
	return sock, client(sock)
}

func me() uint32 { return uint32(os.Getuid()) } // #nosec G115 -- a uid

func TestSocketServesAnAllowedPeer(t *testing.T) {
	_, hc := serve(t, func(uid uint32) bool { return uid == me() })
	for _, opt := range [][]connect.ClientOption{nil, {connect.WithGRPC()}} {
		c := initv1connect.NewServicesServiceClient(hc, "http://init.sock", opt...)
		ctx := context.Background()
		if _, err := c.Start(ctx, connect.NewRequest(&initv1.StartRequest{Name: "sleeper"})); err != nil {
			t.Fatal(err)
		}
		st, err := c.Status(ctx, connect.NewRequest(&initv1.StatusRequest{Name: "sleeper"}))
		if err != nil || !st.Msg.GetRunning() {
			t.Fatalf("%v %v", st, err)
		}
		if _, err := c.Stop(ctx, connect.NewRequest(&initv1.StopRequest{Name: "sleeper"})); err != nil {
			t.Fatal(err)
		}
		_, err = c.Start(ctx, connect.NewRequest(&initv1.StartRequest{Name: "nope"}))
		if connect.CodeOf(err) != connect.CodeNotFound {
			t.Fatalf("unknown service: %v", err)
		}
	}
}

func TestSocketRefusesANonRootPeer(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: the peer would be allowed")
	}
	_, hc := serve(t, initapi.RootOnly)
	c := initv1connect.NewServicesServiceClient(hc, "http://init.sock")
	_, err := c.Status(context.Background(), connect.NewRequest(&initv1.StatusRequest{Name: "sleeper"}))
	if err == nil {
		t.Fatal("a non-root peer got through")
	}
}

func TestLaterServicesAnswerUnimplemented(t *testing.T) {
	_, hc := serve(t, func(uid uint32) bool { return uid == me() })
	_, err := initv1connect.NewKeyCustodyServiceClient(hc, "http://init.sock").Mode(context.Background(), connect.NewRequest(&initv1.ModeRequest{}))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("got %v", err)
	}
}
