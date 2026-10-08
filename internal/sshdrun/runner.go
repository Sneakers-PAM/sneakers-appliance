// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package sshdrun is sneakers-sshd-run (spec 2, Section 3.3): it renders
// sshd's config from the access store, has the pinned sshd -t check them,
// swaps them in, and runs OpenSSH sshd on them. On a SIGHUP from accessd,
// or when netd reports new management addresses, it renders and checks
// again and tells sshd (SIGHUP) only after the check passed; a render sshd
// refuses is logged and audited, and the old config stays.
//
// It stays sshd's parent instead of exec'ing it, because the reload has to
// run sshd -t before sshd sees anything.
package sshdrun

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshconfig"
)

// Daemon is the running sshd.
type Daemon interface {
	Signal(os.Signal) error
	Wait() error
}

// Options wire a Runner.
type Options struct {
	Paths sshconfig.Paths
	Port  uint16
	// StateDir is /var/lib/sneakers: access/store.json.
	StateDir string
	// Addresses are the management addresses sshd listens on (netd).
	Addresses func(ctx context.Context) ([]netip.Addr, error)
	// AddressWait is how often Prepare asks again while there's no
	// address; zero is 2 s.
	AddressWait time.Duration
	// Check is sshd -t on a rendered directory.
	Check func(dir string) error
	// Start runs sshd on the config file.
	Start  func(config string) (Daemon, error)
	Audit  osaudit.Appender
	Logger log.Logger
	Now    func() time.Time
}

// Runner is one sshd-run.
type Runner struct {
	o       Options
	loaded  [32]byte
	sshd    Daemon
	reloads atomic.Int64
}

// New returns a Runner.
func New(o Options) *Runner {
	if o.Logger == nil {
		o.Logger = log.Nop()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.AddressWait == 0 {
		o.AddressWait = 2 * time.Second
	}
	if o.Paths.ConfigDir == "" {
		o.Paths = sshconfig.DefaultPaths()
	}
	return &Runner{o: o}
}

func (r *Runner) configFile() string { return filepath.Join(r.o.Paths.ConfigDir, "sshd_config") }

// Reloads counts the reloads handled, for tests.
func (r *Runner) Reloads() int64 { return r.reloads.Load() }

func signInAdmin(st access.State) bool {
	for i := range st.Admins {
		if st.Admins[i].HasCredentials() {
			return true
		}
	}
	return false
}

// Input is what the next render is made from: the store and the
// addresses. It refuses while no admin can sign in: sshd stays off until
// the first admin exists.
func (r *Runner) Input(ctx context.Context) (sshconfig.Input, error) {
	st, err := access.ReadState(filepath.Join(r.o.StateDir, "access"))
	if err != nil {
		return sshconfig.Input{}, err
	}
	if !signInAdmin(st) {
		return sshconfig.Input{}, codes.New(codes.AccessNoAdmin, "no admin can sign in yet; sshd starts once the first admin exists")
	}
	addrs, err := r.o.Addresses(ctx)
	if err != nil {
		return sshconfig.Input{}, fmt.Errorf("sshd-run: the management addresses: %w", err)
	}
	if len(addrs) == 0 {
		return sshconfig.Input{}, errors.New("sshd-run: no management address yet")
	}
	return sshconfig.Input{ListenAddrs: addrs, State: st, Paths: r.o.Paths, Port: r.o.Port}, nil
}

// Prepare makes the first render: it refuses while no admin can sign in,
// waits for a management address, and installs the checked config.
func (r *Runner) Prepare(ctx context.Context) error {
	lg := r.o.Logger
	for {
		in, err := r.Input(ctx)
		if codes.Is(err, codes.AccessNoAdmin) {
			lg.Error(err, "sshd-run: refusing to start")
			return err
		}
		if err == nil {
			if _, err := sshconfig.Install(in, r.o.Check); err != nil {
				lg.Error(err, "sshd-run: the first config didn't pass sshd -t")
				r.audit(err)
				return err
			}
			lg.Info("sshd-run: config installed", log.F("listen", len(in.ListenAddrs)))
			return nil
		}
		lg.Warn("sshd-run: not ready to render", log.F("error", err.Error()))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(r.o.AddressWait):
		}
	}
}

func (r *Runner) hash() ([32]byte, error) {
	b, err := os.ReadFile(r.configFile())
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// Run starts sshd on the installed config and reloads on every send on
// reload until ctx ends (sshd gets a SIGTERM) or sshd exits.
func (r *Runner) Run(ctx context.Context, reload <-chan struct{}) error {
	lg := r.o.Logger
	h, err := r.hash()
	if err != nil {
		return fmt.Errorf("sshd-run: %w", err)
	}
	d, err := r.o.Start(r.configFile())
	if err != nil {
		return fmt.Errorf("sshd-run: start sshd: %w", err)
	}
	r.sshd, r.loaded = d, h
	exited := make(chan error, 1)
	go func() { exited <- d.Wait() }()
	lg.Info("sshd-run: sshd started", log.F("config", r.configFile()))
	for {
		select {
		case <-ctx.Done():
			lg.Info("sshd-run: stopping sshd")
			_ = d.Signal(syscall.SIGTERM)
			select {
			case <-exited:
			case <-time.After(10 * time.Second):
				_ = d.Signal(syscall.SIGKILL)
				<-exited
			}
			return nil
		case err := <-exited:
			if err == nil {
				err = errors.New("sshd exited")
			}
			lg.Error(err, "sshd-run: sshd ended")
			return fmt.Errorf("sshd-run: %w", err)
		case <-reload:
			r.reload(ctx)
			r.reloads.Add(1)
		}
	}
}

// reload renders and checks again, and signals sshd when the config it
// runs differs from the installed one.
func (r *Runner) reload(ctx context.Context) {
	lg := r.o.Logger
	in, err := r.Input(ctx)
	if err == nil {
		_, err = sshconfig.Install(in, r.o.Check)
	}
	if err != nil {
		lg.Error(err, "sshd-run: the new config wasn't installed; sshd keeps the old one")
		r.audit(err)
		return
	}
	h, err := r.hash()
	if err != nil {
		lg.Error(err, "sshd-run: the installed config can't be read")
		return
	}
	if h == r.loaded {
		lg.Debug("sshd-run: config unchanged")
		return
	}
	if err := r.sshd.Signal(syscall.SIGHUP); err != nil {
		lg.Error(err, "sshd-run: sshd wasn't told to reload")
		return
	}
	r.loaded = h
	lg.Info("sshd-run: sshd told to reload", log.F("listen", len(in.ListenAddrs)))
}

func (r *Runner) audit(err error) {
	if r.o.Audit == nil {
		return
	}
	e := osaudit.Entry{Time: r.o.Now().UTC(), Actor: "sneakers-sshd-run", Action: "sshd.config", Target: r.configFile(),
		Outcome: "refused", Detail: map[string]string{"error": err.Error()}}
	if c, ok := codes.Of(err); ok {
		e.Code = codes.Symbol(c)
	}
	if aerr := r.o.Audit.Append(e); aerr != nil {
		r.o.Logger.Error(aerr, "sshd-run: the refusal wasn't audited")
	}
}
