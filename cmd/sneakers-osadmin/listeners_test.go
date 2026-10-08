// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	log "github.com/Bugs5382/go-log"
)

// TestARebindKeepsTheListenersThatStay: a host name change (or an added
// address) must not drop the browser's connection on an address that
// stays, or the Network page can't confirm the change that caused it.
func TestARebindKeepsTheListenersThatStay(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	tmp := httptest.NewTLSServer(ok)
	cert := tmp.TLS.Certificates[0]
	tmp.Close()

	ls := newListeners(ok, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }, "0", log.Nop())
	t.Cleanup(ls.closeAll)
	if err := ls.sync([]string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	url := "https://" + ls.addr("127.0.0.1") + "/"
	var dials atomic.Int32
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- the test's own self-signed listener
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
	get := func() error {
		res, err := client.Get(url)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, res.Body)
		return res.Body.Close()
	}
	if err := get(); err != nil {
		t.Fatal(err)
	}
	if err := ls.sync([]string{"127.0.0.1", "127.0.0.2"}); err != nil {
		t.Fatal(err)
	}
	if err := get(); err != nil {
		t.Fatalf("the address that stayed stopped answering: %v", err)
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("%d connections, want the first one kept", n)
	}
	if err := ls.sync([]string{"127.0.0.2"}); err != nil {
		t.Fatal(err)
	}
	client.CloseIdleConnections()
	if err := get(); err == nil {
		t.Fatal("the removed address still answers")
	}
}
