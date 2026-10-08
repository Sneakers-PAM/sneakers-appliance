// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accounts"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshconfig"
)

// Changed renders every file that follows the store from st: passwd,
// group and shadow, the login homes, and sshd's config. It is the store's OnChange. The files stay in /run when
// accessd stops, so sshd keeps authenticating logins.
func (s *Server) Changed(st access.State) {
	s.renderMu.Lock()
	defer s.renderMu.Unlock()
	started := time.Now()
	p := s.o.Paths
	if err := accounts.Render(st, p.AccountsDir()); err != nil {
		s.o.Logger.Error(err, "accessd: accounts not rendered", log.F("version", st.Version))
	}
	if err := accounts.MakeHomes(st, p.HomesDir()); err != nil {
		s.o.Logger.Error(err, "accessd: login homes not made", log.F("version", st.Version))
	}
	if !osadmin.HasSignInAdmin(st) {
		s.o.Logger.Debug("accessd: no admin can sign in yet; sshd's files wait", log.F("version", st.Version))
	} else if err := s.renderSSH(st); err != nil {
		s.o.Logger.Error(err, "accessd: sshd files not rendered; the previous ones stay", log.F("version", st.Version))
	}
	s.o.Logger.Info("accessd: rendered from the store", log.F("version", st.Version), log.F("ms", time.Since(started).Milliseconds()))
}

func (s *Server) sshPaths() sshconfig.Paths {
	sp := sshconfig.DefaultPaths()
	sp.ConfigDir = s.o.Paths.SSHDir()
	return sp
}

// renderSSH renders sshd's config from st, has the pinned sshd check it
// and swaps it in (sshconfig.Install); sneakers-sshd-run gets a SIGHUP when
// it changed, and renders and checks again before it tells sshd. A revoked
// key needs none: sshd reads the revocation list at each login.
func (s *Server) renderSSH(st access.State) error {
	if s.o.Network == nil {
		return errors.New("no netd client")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ns, err := s.o.Network.Status(ctx, connect.NewRequest(&netdv1.StatusRequest{}))
	if err != nil {
		return fmt.Errorf("netd: %w", err)
	}
	var listen []netip.Addr
	for _, a := range Bindable(ns.Msg.GetManagementAddresses()) {
		listen = append(listen, netip.MustParseAddr(a))
	}
	in := sshconfig.Input{ListenAddrs: listen, State: st, Paths: s.sshPaths()}
	var check func(string) error
	if s.o.Paths.SSHD != "" {
		check = func(dir string) error { return sshconfig.Check(s.o.Paths.SSHD, dir) }
	}
	changed, err := sshconfig.Install(in, check)
	if err != nil {
		return err
	}
	s.o.Logger.Debug("accessd: sshd files rendered", log.F("listen", len(listen)), log.F("configChanged", changed))
	if changed {
		s.reloadSSHD()
	}
	return nil
}

// reloadSSHD sends sneakers-sshd-run a SIGHUP, which has it render and
// check again and then tell sshd; with no pid file sshd isn't running and
// picks the config up when it starts.
func (s *Server) reloadSSHD() {
	b, err := os.ReadFile(s.o.Paths.SSHDPidFile())
	if err != nil {
		s.o.Logger.Debug("accessd: sshd isn't running; nothing to reload")
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		s.o.Logger.Warn("accessd: sshd's pid file doesn't hold a pid", log.F("file", s.o.Paths.SSHDPidFile()))
		return
	}
	if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
		s.o.Logger.Warn("accessd: sshd reload failed", log.F("pid", pid), log.F("error", err.Error()))
		return
	}
	s.o.Logger.Info("accessd: sshd told to re-read its config", log.F("pid", pid))
}
