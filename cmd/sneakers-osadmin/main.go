// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Command sneakers-osadmin serves the :8443 appliance admin as the
// unprivileged osadmin user, on the management addresses only, with its
// own TLS certificate. It serves the static pages and forwards the API to
// sneakers-accessd on access.sock, which holds the sessions and the store
// and decides every call.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/front"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sigbundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/webslots"
)

// Port is the appliance admin's port.
const Port = "8443"

type config struct {
	state, assets, web, accessSock string
}

func main() {
	var c config
	flag.StringVar(&c.state, "state", "/var/lib/sneakers", "the state volume (osadmin writes only its own directory)")
	flag.StringVar(&c.assets, "assets", "/usr/share/sneakers/osadmin", "the built-in admin pages, served when no Base Web is installed or it doesn't load")
	flag.StringVar(&c.web, "web", webslots.Dir, "the Base Web slots")
	flag.StringVar(&c.accessSock, "access-socket", accessapi.SocketPath, "accessd's socket")
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

func unixTransport(sock string) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", sock)
		},
		ResponseHeaderTimeout: 2 * time.Minute,
	}
}

func run(ctx context.Context, c config, lg log.Logger) error {
	if os.Geteuid() == 0 {
		return errors.New("sneakers-osadmin runs as the osadmin user, not root")
	}
	tr := unixTransport(c.accessSock)
	binding := accessv1connect.NewBindingServiceClient(&http.Client{Timeout: 30 * time.Second, Transport: tr}, "http://access.sock")
	paths := osadmin.Paths{State: c.state}
	var builtin fs.FS
	if st, err := os.Stat(c.assets); err == nil && st.IsDir() {
		builtin = os.DirFS(c.assets)
	} else {
		lg.Warn("osadmin: no built-in admin pages; serving the API only until a Base Web is installed", log.F("path", c.assets))
	}
	live := webslots.NewLive(builtin, release.Version)
	if err := watchWeb(ctx, c, paths, builtin, live, lg); err != nil {
		return err
	}
	f := front.New(front.Options{
		Backend:    &url.URL{Scheme: "http", Host: "access.sock"},
		Transport:  tr,
		Assets:     live,
		StatusFile: accessapi.StatusFile,
		WebVersion: live.Version,
		Logger:     lg,
	})

	// Bind only the management addresses accessd reports (from netd), and
	// rebind (with a matching certificate) whenever they or the host name
	// change. Listeners on addresses that stay keep running.
	var src *osadmin.CertSource
	var ls *listeners
	defer func() {
		if ls != nil {
			ls.closeAll()
		}
	}()
	for {
		host, addrs, err := waitForAddresses(ctx, binding, lg)
		if err != nil {
			return nil
		}
		cert, info, err := osadmin.EnsureCert(paths.OwnDir(), host, addrs, time.Now())
		if err != nil {
			return err
		}
		lg.Info("osadmin: certificate ready", log.F("fingerprint", info.Fingerprint), log.F("expires", info.Expires), log.F("selfSigned", info.SelfSigned))
		// accessd swaps the files when an owner assigns a certificate, and
		// EnsureCert rewrites them for a new name; the source re-reads them,
		// so the listeners keep running.
		if src == nil {
			src = osadmin.NewCertSource(paths.OwnDir(), cert, lg)
			ls = newListeners(f.Handler(), src.GetCertificate, Port, lg)
		}
		if err := ls.sync(addrs); err != nil {
			return err
		}
		if !watch(ctx, binding, host, addrs) {
			lg.Info("osadmin: stopped")
			return nil
		}
		lg.Info("osadmin: management addresses or host name changed; rebinding")
	}
}

// webEvery is how often the served pages are checked against the
// current web slot.
const webEvery = time.Second

// watchWeb serves the current Base Web slot when it loads and fits the
// running Base OS, else the built-in pages, and follows the slot's
// changes until ctx ends.
func watchWeb(ctx context.Context, c config, paths osadmin.Paths, builtin fs.FS, live *webslots.Live, lg log.Logger) error {
	pins, err := release.Load()
	if err != nil {
		return err
	}
	key, err := sigbundle.ParsePublicKey(pins.ReleaseKeyPEM)
	if err != nil {
		return err
	}
	w := &webslots.Watcher{Slots: webslots.Slots{Dir: c.web}, Key: key, Channel: pins.Channel, BaseOS: release.Version, Builtin: builtin, BuiltinVersion: release.Version,
		Live: live, StatusFile: filepath.Join(paths.OwnDir(), osadmin.WebServedFile), Logger: lg}
	w.Sync()
	go w.Run(ctx, webEvery)
	return nil
}

func addresses(ctx context.Context, binding accessv1connect.BindingServiceClient) (string, []string, error) {
	res, err := binding.GetBinding(ctx, connect.NewRequest(&accessv1.GetBindingRequest{}))
	if err != nil {
		return "", nil, err
	}
	addrs := slices.Clone(res.Msg.GetManagementAddresses())
	slices.Sort(addrs)
	return res.Msg.GetHostname(), addrs, nil
}

func waitForAddresses(ctx context.Context, binding accessv1connect.BindingServiceClient, lg log.Logger) (string, []string, error) {
	for {
		host, addrs, err := addresses(ctx, binding)
		if err == nil && len(addrs) > 0 {
			return host, addrs, nil
		}
		lg.Warn("osadmin: waiting for a management address from accessd", log.F("error", fmt.Sprint(err)))
		select {
		case <-ctx.Done():
			return "", nil, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// watch returns true when the host name or addresses change, false when
// ctx ends.
func watch(ctx context.Context, binding accessv1connect.BindingServiceClient, host string, addrs []string) bool {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
		}
		h, a, err := addresses(ctx, binding)
		if err == nil && len(a) > 0 && (h != host || !slices.Equal(a, addrs)) {
			return true
		}
	}
}
