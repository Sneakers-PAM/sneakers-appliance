// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package fixtures

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// docker's port proxy accepts a connection and drops it before the registry
// in the container listens. That is an EOF, not a refused connection, and the
// wait must not call it ready.
func TestWaitRegistryIgnoresAProxyThatAcceptsAndDrops(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	var drops atomic.Int32
	drops.Store(3)
	go func() {
		for drops.Load() > 0 {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			drops.Add(-1)
			_ = c.Close()
		}
		_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	}()
	if err := waitRegistry(context.Background(), ln.Addr().String(), 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if n := drops.Load(); n != 0 {
		t.Fatalf("answered ready with %d drops left", n)
	}
}

func TestWaitRegistryGivesUp(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	if err := waitRegistry(context.Background(), addr, 500*time.Millisecond); err == nil {
		t.Fatal("a closed port is not a registry")
	}
}
