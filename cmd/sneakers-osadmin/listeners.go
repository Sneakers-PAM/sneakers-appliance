// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"slices"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/front"
)

// listeners are the :8443 servers, one per management address. A rebind
// starts and stops only the addresses that changed, so a browser on an
// address that stays keeps its connection: a host name change only swaps
// the certificate, which the source serves to new handshakes.
type listeners struct {
	h       http.Handler
	cert    func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	port    string
	lg      log.Logger
	servers map[string]*http.Server
	bound   map[string]string
}

func newListeners(h http.Handler, cert func(*tls.ClientHelloInfo) (*tls.Certificate, error), port string, lg log.Logger) *listeners {
	return &listeners{h: h, cert: cert, port: port, lg: lg, servers: map[string]*http.Server{}, bound: map[string]string{}}
}

// sync serves exactly addrs.
func (l *listeners) sync(addrs []string) error {
	for a, s := range l.servers {
		if !slices.Contains(addrs, a) {
			l.stop(a, s)
		}
	}
	for _, a := range addrs {
		if _, ok := l.servers[a]; ok {
			l.lg.Debug("osadmin: listener kept", log.F("address", l.bound[a]))
			continue
		}
		if err := l.start(a); err != nil {
			return err
		}
	}
	return nil
}

func (l *listeners) start(a string) error {
	ln, err := net.Listen("tcp", net.JoinHostPort(a, l.port))
	if err != nil {
		return err
	}
	s := &http.Server{
		Handler:           l.h,
		TLSConfig:         &tls.Config{GetCertificate: l.cert, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	go func() {
		if err := s.ServeTLS(front.TLSOnly(ln, l.lg), "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			l.lg.Error(err, "osadmin: listener stopped", log.F("address", ln.Addr().String()))
		}
	}()
	l.servers[a], l.bound[a] = s, ln.Addr().String()
	l.lg.Info("osadmin: listening", log.F("address", ln.Addr().String()))
	return nil
}

func (l *listeners) stop(a string, s *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = s.Shutdown(ctx)
	cancel()
	l.lg.Info("osadmin: listener closed", log.F("address", l.bound[a]))
	delete(l.servers, a)
	delete(l.bound, a)
}

// addr is the host:port the listener on a is bound to.
func (l *listeners) addr(a string) string { return l.bound[a] }

func (l *listeners) closeAll() {
	for a, s := range l.servers {
		l.stop(a, s)
	}
}
