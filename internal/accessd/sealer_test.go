// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd_test

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessd"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/initapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody/keycustodytest"
)

// The user CA goes through init's KeyCustody on init.sock.
func TestTheCustodySealerSealsThroughInit(t *testing.T) {
	kc := keycustody.New(keycustody.Deps{Disk: &keycustodytest.Disk{}, SealedDir: t.TempDir()})
	if err := kc.Initialize(context.Background(), keycustody.ModeKeyfile, keycustody.SBOff); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "init.sock")
	me := uint32(os.Getuid()) // #nosec G115 -- a uid
	srv, err := initapi.Listen(sock, initapi.Options{Allow: func(uid uint32) bool { return uid == me }, KeyCustody: kc})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Stop)
	hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	s := accessd.CustodySealer{Client: initv1connect.NewKeyCustodyServiceClient(hc, "http://init.sock")}
	if _, ok, err := s.Unseal("ssh-user-ca"); err != nil || ok {
		t.Fatalf("an item never sealed: ok=%v %v", ok, err)
	}
	if err := s.Seal("ssh-user-ca", []byte("lab CA")); err != nil {
		t.Fatal(err)
	}
	b, ok, err := s.Unseal("ssh-user-ca")
	if err != nil || !ok || !bytes.Equal(b, []byte("lab CA")) {
		t.Fatalf("unseal: ok=%v %v", ok, err)
	}
}
