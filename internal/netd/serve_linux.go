// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package netd

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/initapi"
)

// Listen serves d's API on the unix socket at path, to root peers only
// (SO_PEERCRED): osadmin and the closed shell reach netd through accessd.
func Listen(path string, d *Daemon, lg log.Logger) (*http.Server, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	mux := http.NewServeMux()
	p, h := d.Handler()
	mux.Handle(p, h)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	hs := &http.Server{Handler: mux, Protocols: protocols, ConnContext: initapi.PeerContext, ReadHeaderTimeout: 10 * time.Second}
	logf := func(format string, args ...any) { lg.Warn(fmt.Sprintf(format, args...)) }
	root := func(uid uint32) bool { return uid == 0 }
	go func() {
		if err := hs.Serve(initapi.PeerListener(ln, root, logf)); err != nil && !errors.Is(err, http.ErrServerClosed) {
			lg.Error(err, "netd: socket stopped")
		}
	}()
	return hs, nil
}
