// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Command sneakers-accessd is the root access service: the access store,
// the sign-in codes and sessions, the OS audit log, the accounts and sshd
// files rendered from the store, and the backend of the :8443 API, served
// on /run/sneakers/access.sock to root, the closed shell's admin uids and
// sneakers-osadmin, each told apart by SO_PEERCRED.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"filippo.io/age"
	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1/netdv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessd"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accounts"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevation"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/enrol"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/initapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/secureboot"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/ukikey"
)

type config struct {
	state, run, socket, initSock, netdSock, esp, sshd string
}

func main() {
	var c config
	flag.StringVar(&c.state, "state", "/var/lib/sneakers", "the state volume")
	flag.StringVar(&c.run, "run", "/run/sneakers", "where the rendered files and the socket live")
	flag.StringVar(&c.socket, "socket", accessapi.SocketPath, "accessd's socket")
	flag.StringVar(&c.initSock, "init-socket", initapi.SocketPath, "init's socket")
	flag.StringVar(&c.netdSock, "netd-socket", "/run/sneakers/netd.sock", "netd's socket")
	flag.StringVar(&c.esp, "esp", "/run/sneakers/esp", "where init mounts the ESP (the booted UKI carries the update key)")
	flag.StringVar(&c.sshd, "sshd", "/usr/sbin/sshd", "the pinned sshd that checks every rendered config")
	flag.Parse()
	lg := log.NewLoggerWithOptions("sneakers-accessd", log.WithOutput(os.Stderr), log.WithDefaultFormat(log.FormatJSON), log.WithDefaultLevel(log.LevelError))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := run(ctx, c, lg); err != nil {
		lg.Error(err, "accessd: fatal")
		_, _ = fmt.Fprintln(os.Stderr, "sneakers-accessd:", codes.Describe(err))
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
	if err := dirs(paths); err != nil {
		return err
	}
	audit, err := osaudit.Open(filepath.Join(c.state, "os-audit"), osaudit.Options{Logger: lg})
	if err != nil {
		return err
	}
	var d *accessd.Server
	rerender := func() {
		if d != nil {
			d.Rerender()
		}
	}
	// The keys the store already revoked go on the first revocation list
	// the elevation service writes; from then on the store's every write
	// rewrites it (access.Options.Revoke).
	stored, err := access.ReadState(filepath.Join(c.state, "access"))
	if err != nil {
		return err
	}
	revokedKeys, err := stored.RevokedPublicKeys()
	if err != nil {
		return err
	}
	// The user CA is generated here at first boot and kept on the state
	// volume, 0600 root: the interim until init's KeyCustody.Seal is served
	// and the CA moves into it (docs/ssh-and-elevation.md).
	elev, err := elevation.Open(elevation.Options{
		RevokedKeys: revokedKeys,
		SSHDir:      paths.SSHDir(),
		StateFile:   filepath.Join(c.state, "access", "elevation.json"),
		Audit:       audit,
		Logger:      lg,
		OnChange:    rerender,
		Signal: func(pid int) error {
			return accessd.SignalElevated(pid, func(pid int) error { return syscall.Kill(pid, syscall.SIGTERM) })
		},
		Alive: func(pid int) bool { return syscall.Kill(pid, 0) == nil },
	})
	if err != nil {
		return err
	}
	d = accessd.New(accessd.Options{
		Network:    netd,
		Paths:      accessd.Paths{Run: c.run, SSHD: c.sshd},
		StatusFile: filepath.Join(c.run, "access", "status.json"),
		Elevation:  elev,
		HostKeyDir: paths.SSHDir(),
		AuditDir:   audit.Dir(),
		Logger:     lg,
	})
	var api *osadmin.Server
	store, err := access.Open(filepath.Join(c.state, "access"), access.Options{
		Stage:    func() (bool, bool) { return true, api != nil && api.SetupDone() },
		Logger:   lg,
		OnChange: d.Changed,
		Revoke:   elev.RevokeLoginKeys,
	})
	if err != nil {
		return err
	}
	d.SetEnrolment(enrol.New(enrol.Options{Store: store, Audit: audit, Logger: lg, OnChange: rerender}))
	go audit.RunRetention(ctx, 24*time.Hour)
	pins, perr := release.Load()
	if perr != nil {
		lg.Error(perr, "accessd: this build carries no release pins; updates can't be verified, so none will stage")
	}
	api = osadmin.New(osadmin.Options{
		Access: store, Audit: audit, Clock: clock.Real{},
		KeyCustody: initv1connect.NewKeyCustodyServiceClient(ic, "http://init.sock"),
		Image:      initv1connect.NewImageServiceClient(ic, "http://init.sock"),
		Power:      initv1connect.NewPowerServiceClient(ic, "http://init.sock"),
		Network:    netd,
		Paths:      paths,
		CertDir:    paths.OwnDir(),
		Elevation:  elev,
		Logger:     lg,
		Upgrade: osadmin.UpgradeOptions{
			Channel: pins.Channel, ReleaseKeyPEM: pins.ReleaseKeyPEM,
			// The update key is read from the running UKI on each use and
			// never written to disk; sneakers-upgraded takes this over
			// when it lands (the upgrades design).
			UpdateKey: func() (age.Identity, error) {
				return ukikey.Running(secureboot.Efivarfs{Dir: secureboot.DefaultEfivarfs}, os.DirFS(c.esp))
			},
		},
	})
	d.Attach(store, api)

	srv, err := listen(c.socket, d, lg)
	if err != nil {
		return err
	}
	defer func() { _ = srv.Close() }()
	ready := filepath.Join(c.run, filepath.Base(accessapi.ReadyFile))
	if err := os.WriteFile(ready, nil, 0o644); err != nil { // #nosec G306 -- an empty readiness marker
		return err
	}
	defer func() { _ = os.Remove(ready) }()
	lg.Info("accessd: ready", log.F("socket", c.socket))

	d.RefreshStatus(ctx)
	minute := time.NewTicker(time.Minute)
	defer minute.Stop()
	for {
		select {
		case <-ctx.Done():
			lg.Info("accessd: stopped")
			return nil
		case <-minute.C:
			d.Tick()
			api.UpgradeWindowTick(ctx)
			d.RefreshStatus(ctx)
		}
	}
}

// dirs makes osadmin's own directory (its certificate, written as the
// osadmin user; a certificate an earlier root osadmin left there is handed
// over) and the API's root-only one.
func dirs(p osadmin.Paths) error {
	if err := os.MkdirAll(p.APIDir(), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(p.OwnDir(), 0o700); err != nil {
		return err
	}
	if err := os.Chown(p.OwnDir(), accounts.OsadminUID, accounts.OsadminUID); err != nil {
		return err
	}
	for _, name := range []string{"tls.crt", "tls.key"} {
		err := os.Lchown(filepath.Join(p.OwnDir(), name), accounts.OsadminUID, accounts.OsadminUID)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// listen serves access.sock: mode 0666, since admin uids and osadmin
// connect, and SO_PEERCRED decides who is let through.
func listen(path string, d *accessd.Server, lg log.Logger) (*http.Server, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil { // #nosec G302 -- the peer uid is checked on every connection
		_ = ln.Close()
		return nil, err
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	hs := &http.Server{Handler: d.Handler(), Protocols: protocols, ConnContext: initapi.PeerContext, ReadHeaderTimeout: 10 * time.Second}
	logf := func(format string, args ...any) { lg.Warn(fmt.Sprintf(format, args...)) }
	go func() {
		if err := hs.Serve(initapi.PeerListener(ln, accessd.PeerAllowed, logf)); err != nil && !errors.Is(err, http.ErrServerClosed) {
			lg.Error(err, "accessd: socket stopped")
		}
	}()
	return hs, nil
}
