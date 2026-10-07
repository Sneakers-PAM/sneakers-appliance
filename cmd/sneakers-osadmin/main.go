// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Command sneakers-osadmin serves the :8443 appliance admin on the
// management addresses only, with its own TLS certificate, and the local
// socket the closed shell and the console use to approve a sign-in.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1/netdv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/initapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

// Port is the appliance admin's port.
const Port = "8443"

type config struct {
	state, assets, initSock, netdSock, localSock string
}

func main() {
	var c config
	flag.StringVar(&c.state, "state", "/var/lib/sneakers", "the state volume")
	flag.StringVar(&c.assets, "assets", "/usr/share/sneakers/osadmin", "the static admin pages")
	flag.StringVar(&c.initSock, "init-socket", initapi.SocketPath, "init's socket")
	flag.StringVar(&c.netdSock, "netd-socket", "/run/sneakers/netd.sock", "netd's socket")
	flag.StringVar(&c.localSock, "socket", "/run/sneakers/osadmin.sock", "the local socket for the shell and the console")
	flag.Parse()
	lg := log.NewLoggerWithOptions("sneakers-osadmin", log.WithOutput(os.Stderr), log.WithDefaultFormat(log.FormatJSON), log.WithDefaultLevel(log.LevelError))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := run(ctx, c, lg); err != nil {
		lg.Error(err, "osadmin: fatal")
		_, _ = fmt.Fprintln(os.Stderr, "sneakers-osadmin:", codes.Describe(err))
		os.Exit(1)
	}
}

func unixClient(sock string) *http.Client {
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
}

func run(ctx context.Context, c config, lg log.Logger) error {
	ic, nc := unixClient(c.initSock), unixClient(c.netdSock)
	netd := netdv1connect.NewNetworkServiceClient(nc, "http://netd.sock")
	paths := osadmin.Paths{State: c.state}
	var srv *osadmin.Server
	store, err := access.Open(filepath.Join(c.state, "access"), access.Options{
		Stage:  func() (bool, bool) { return true, srv != nil && srv.SetupDone() },
		Logger: lg,
	})
	if err != nil {
		return err
	}
	audit, err := osaudit.Open(filepath.Join(c.state, "os-audit"), osaudit.Options{Logger: lg})
	if err != nil {
		return err
	}
	go audit.RunRetention(ctx, 24*time.Hour)
	var assets fs.FS
	if st, err := os.Stat(c.assets); err == nil && st.IsDir() {
		assets = os.DirFS(c.assets)
	} else {
		lg.Warn("osadmin: no admin pages installed; serving the API only", log.F("path", c.assets))
	}
	opts := osadmin.Options{
		Access: store, Audit: audit, Clock: clock.Real{},
		KeyCustody: initv1connect.NewKeyCustodyServiceClient(ic, "http://init.sock"),
		Image:      initv1connect.NewImageServiceClient(ic, "http://init.sock"),
		Power:      initv1connect.NewPowerServiceClient(ic, "http://init.sock"),
		Network:    netd,
		Paths:      paths,
		Assets:     assets,
		Logger:     lg,
	}
	srv = osadmin.New(opts)

	local, err := listenLocal(c.localSock, srv, lg)
	if err != nil {
		return err
	}
	defer func() { _ = local.Close() }()

	// Bind only the management addresses netd reports, and rebind (with a
	// matching certificate) whenever they or the host name change.
	for {
		host, addrs, err := waitForAddresses(ctx, netd, lg)
		if err != nil {
			return nil
		}
		cert, info, err := osadmin.EnsureCert(paths.OwnDir(), host, addrs, time.Now())
		if err != nil {
			return err
		}
		lg.Info("osadmin: certificate ready", log.F("fingerprint", info.Fingerprint), log.F("expires", info.Expires))
		srv.SetCert(info)
		servers, err := serve(srv.Handler(), cert, addrs, lg)
		if err != nil {
			return err
		}
		changed := watch(ctx, netd, host, addrs)
		for _, s := range servers {
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = s.Shutdown(sctx)
			cancel()
		}
		if !changed {
			lg.Info("osadmin: stopped")
			return nil
		}
		lg.Info("osadmin: management addresses changed; rebinding")
	}
}

func listenLocal(path string, srv *osadmin.Server, lg log.Logger) (*http.Server, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	// Admin uids connect too; SO_PEERCRED decides who is let through.
	if err := os.Chmod(path, 0o666); err != nil { // #nosec G302 -- the peer uid is checked on every connection
		_ = ln.Close()
		return nil, err
	}
	hs := &http.Server{Handler: srv.LocalHandler(), ConnContext: initapi.PeerContext, ReadHeaderTimeout: 10 * time.Second}
	logf := func(format string, args ...any) { lg.Warn(fmt.Sprintf(format, args...)) }
	go func() { _ = hs.Serve(initapi.PeerListener(ln, osadmin.LocalPeerAllowed, logf)) }()
	lg.Info("osadmin: local socket listening", log.F("socket", path))
	return hs, nil
}

func addresses(ctx context.Context, netd netdv1connect.NetworkServiceClient) (string, []string, error) {
	st, err := netd.Status(ctx, connect.NewRequest(&netdv1.StatusRequest{}))
	if err != nil {
		return "", nil, err
	}
	var addrs []string
	for _, a := range st.Msg.GetManagementAddresses() {
		if ip, _, err := net.ParseCIDR(a); err == nil {
			a = ip.String()
		}
		if ip := net.ParseIP(a); ip != nil && !ip.IsLinkLocalUnicast() {
			addrs = append(addrs, ip.String())
		}
	}
	slices.Sort(addrs)
	return st.Msg.GetHostname(), addrs, nil
}

func waitForAddresses(ctx context.Context, netd netdv1connect.NetworkServiceClient, lg log.Logger) (string, []string, error) {
	for {
		host, addrs, err := addresses(ctx, netd)
		if err == nil && len(addrs) > 0 {
			return host, addrs, nil
		}
		lg.Warn("osadmin: waiting for a management address from netd", log.F("error", fmt.Sprint(err)))
		select {
		case <-ctx.Done():
			return "", nil, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// watch returns true when the host name or addresses change, false when
// ctx ends.
func watch(ctx context.Context, netd netdv1connect.NetworkServiceClient, host string, addrs []string) bool {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
		}
		h, a, err := addresses(ctx, netd)
		if err == nil && len(a) > 0 && (h != host || !slices.Equal(a, addrs)) {
			return true
		}
	}
}

func serve(h http.Handler, cert tls.Certificate, addrs []string, lg log.Logger) ([]*http.Server, error) {
	var out []*http.Server
	for _, a := range addrs {
		ln, err := net.Listen("tcp", net.JoinHostPort(a, Port))
		if err != nil {
			for _, s := range out {
				_ = s.Close()
			}
			return nil, err
		}
		s := &http.Server{
			Handler:           h,
			TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       2 * time.Minute,
		}
		go func() {
			if err := s.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				lg.Error(err, "osadmin: listener stopped", log.F("address", ln.Addr().String()))
			}
		}()
		lg.Info("osadmin: listening", log.F("address", ln.Addr().String()))
		out = append(out, s)
	}
	return out, nil
}
