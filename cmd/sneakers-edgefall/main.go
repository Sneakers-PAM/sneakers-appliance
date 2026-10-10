// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Command sneakers-edgefall is the product edge's fallback
// (docs/edge-fallback.md). `prepare` runs as root before every start and
// hands it the box's certificate; `serve` runs as the edgefall user with
// only CAP_NET_BIND_SERVICE. It serves the box state, the poller and the
// branded box-state page on loopback for Traefik, and on 80 and 443 itself
// while k0s doesn't run. It never serves product content or proxies.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accounts"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxstate"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/brand"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/edgefall"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/product"
)

// pollEvery is how often accessd is asked; the poller asks edgefall every
// second, so a reboot reaches an open tab within about two.
const pollEvery = 500 * time.Millisecond

// askTimeout bounds one GetPhase.
const askTimeout = time.Second

type config struct {
	osadminDir, tlsDir, accessSock, boxState, brandDir, local, https, http, push string
}

func main() {
	var c config
	fs := flag.NewFlagSet("sneakers-edgefall", flag.ExitOnError)
	fs.StringVar(&c.osadminDir, "osadmin-dir", "/var/lib/sneakers/osadmin", "osadmin's directory, where the box's :8443 certificate is")
	fs.StringVar(&c.tlsDir, "tls-dir", "/run/sneakers/edgefall", "edgefall's own copy of the certificate")
	fs.StringVar(&c.accessSock, "access-socket", accessapi.SocketPath, "accessd's socket")
	fs.StringVar(&c.boxState, "box-state", boxstate.File, "init's announcement of a reboot or a shutdown")
	fs.StringVar(&c.brandDir, "brand-dir", filepath.Join(product.Dir, "current", brand.Dir), "the installed product bundle's brand, read-only")
	fs.StringVar(&c.local, "local", edgefall.LocalAddr, "the loopback address Traefik reaches for /_box/ and its error pages")
	fs.StringVar(&c.https, "https", ":443", "the edge's https address, held while k0s doesn't run")
	fs.StringVar(&c.http, "http", ":80", "the edge's http address, held with https")
	fs.StringVar(&c.push, "push-socket", edgefall.PushSocket, "where accessd pushes the box state the moment it changes (only root and edgefall reach it)")
	cmd := "serve"
	args := os.Args[1:]
	if len(args) > 0 && (args[0] == "prepare" || args[0] == "serve") {
		cmd, args = args[0], args[1:]
	}
	_ = fs.Parse(args)
	lg := log.NewLoggerWithOptions("sneakers-edgefall", log.WithOutput(os.Stderr), log.WithDefaultFormat(log.FormatJSON), log.WithDefaultLevel(log.LevelError))
	var err error
	if cmd == "prepare" {
		err = prepare(c, lg)
	} else {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer stop()
		err = serve(ctx, c, lg)
	}
	if err != nil {
		lg.Error(err, "edgefall: fatal", log.F("command", cmd))
		_, _ = fmt.Fprintln(os.Stderr, "sneakers-edgefall:", err)
		os.Exit(1)
	}
}

func prepare(c config, lg log.Logger) error {
	if os.Geteuid() != 0 {
		return errors.New("prepare runs as root, before serve")
	}
	if err := edgefall.Prepare(c.osadminDir, c.tlsDir, accounts.EdgefallUID, accounts.EdgefallUID); err != nil {
		return err
	}
	if _, err := edgefall.LoadCert(c.tlsDir)(); err != nil {
		lg.Warn("edgefall: no box certificate yet; 443 isn't answered while k0s is down", log.F("error", err.Error()))
	} else {
		lg.Info("edgefall: the box certificate is in place")
	}
	return nil
}

func serve(ctx context.Context, c config, lg log.Logger) error {
	if os.Geteuid() == 0 {
		return errors.New("serve runs as the edgefall user, not root")
	}
	if ap, err := netip.ParseAddrPort(c.local); err != nil || !ap.Addr().IsLoopback() {
		return fmt.Errorf("the local address %q must be a loopback address and port", c.local)
	}
	src := phaseSource(c.accessSock)
	w := edgefall.NewWatcher(src, c.boxState, lg)
	h := edgefall.NewServer(w.State)
	h.SetEvents(w.Events())

	ln, err := net.Listen("tcp", c.local)
	if err != nil {
		return err
	}
	cl := edgefall.NewClaimer(edgefall.ClaimOptions{HTTPS: c.https, HTTP: c.http, Cert: edgefall.LoadCert(c.tlsDir), Handler: h, Logger: lg})
	defer cl.Close()
	// The answer waits until 80 and 443 are let go, so Traefik binds them
	// as soon as the edge's start command execs it; how long 443 refused
	// in between goes to the log.
	local := edgefall.HTTPServer(edgefall.LocalHandler(h, func() bool {
		ok := w.Handoff()
		cl.Want(w.Claim())
		if ok {
			go edgefall.WatchTaken(c.https, edgefall.HandoffWait, 100*time.Millisecond, func(gap time.Duration, taken bool) {
				if taken {
					lg.Info("edgefall: the edge took 443", log.F("refusedMs", gap.Milliseconds()))
					return
				}
				lg.Error(nil, "edgefall: nothing took 443 after the handoff", log.F("waited", gap.String()))
			})
		}
		return ok
	}))
	go func() {
		if err := local.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			lg.Error(err, "edgefall: the loopback listener stopped")
		}
	}()
	defer func() { _ = local.Close() }()
	pushSrv, err := servePush(c.push, w, func() { cl.Want(w.Claim()) }, lg)
	if err != nil {
		return err
	}
	defer func() { _ = pushSrv.Close() }()
	lg.Info("edgefall: serving", log.F("push", c.push), log.F("local", c.local), log.F("https", c.https), log.F("http", c.http))

	t := time.NewTicker(pollEvery)
	defer t.Stop()
	for {
		loadBrand(h, c.brandDir, lg)
		w.Poll(ctx)
		cl.Want(w.Claim())
		select {
		case <-ctx.Done():
			lg.Info("edgefall: stopped", log.F("state", string(w.State())))
			return nil
		case <-t.C:
		}
	}
}

// loadBrand picks up the installed product's brand when the current slot
// changes; a malformed one leaves the base look.
func loadBrand(h *edgefall.Server, dir string, lg log.Logger) {
	changed, warn, err := h.LoadBrand(dir)
	switch {
	case !changed:
	case err != nil:
		lg.Warn("edgefall: the product's brand isn't used; the base look stays", log.F("dir", dir), log.F("error", err.Error()))
	default:
		for _, w := range warn {
			lg.Warn("edgefall: "+w, log.F("dir", dir))
		}
		lg.Info("edgefall: the box-state look loaded", log.F("dir", dir))
	}
}

// phaseSource asks accessd's public GetPhase on access.sock, where the
// edgefall uid may ask that and nothing else.
func phaseSource(sock string) edgefall.Source {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: askTimeout}).DialContext(ctx, "unix", sock)
		},
		MaxIdleConns: 1,
	}
	st := osadminv1connect.NewStatusServiceClient(&http.Client{Transport: tr, Timeout: askTimeout}, "http://access.sock")
	return func(ctx context.Context) (edgefall.Phase, error) {
		res, err := st.GetPhase(ctx, connect.NewRequest(&osadminv1.GetPhaseRequest{}))
		if err != nil {
			return edgefall.Phase{}, err
		}
		return edgefall.Phase{State: res.Msg.GetState(), ProductRunning: res.Msg.GetProductRunning(), ProductInstalled: res.Msg.GetProductInstalled()}, nil
	}
}

// servePush listens on the push socket, in edgefall's own 0700 directory:
// only root (accessd) and edgefall reach it.
func servePush(path string, w *edgefall.Watcher, after func(), lg log.Logger) (*http.Server, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("the push socket %s: %w", path, err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	srv := &http.Server{Handler: edgefall.PushHandler(w, after), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			lg.Error(err, "edgefall: the push socket stopped")
		}
	}()
	return srv, nil
}
