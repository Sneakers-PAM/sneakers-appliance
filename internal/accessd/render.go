// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accounts"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshconfig"
)

// Changed renders every file that follows the store from st: passwd,
// group and shadow, the login homes, and sshd's config, authorized keys
// and principals. It is the store's OnChange. The files stay in /run when
// accessd stops, so sshd keeps authenticating logins.
func (s *Server) Changed(st access.State) {
	s.renderMu.Lock()
	defer s.renderMu.Unlock()
	started := time.Now()
	p := s.o.Paths
	if err := accounts.Render(st, false, p.AccountsDir()); err != nil {
		s.o.Logger.Error(err, "accessd: accounts not rendered", log.F("version", st.Version))
	}
	if err := accounts.MakeHomes(st, false, p.HomesDir()); err != nil {
		s.o.Logger.Error(err, "accessd: login homes not made", log.F("version", st.Version))
	}
	if err := s.renderSSH(st); err != nil {
		s.o.Logger.Error(err, "accessd: sshd files not rendered; the previous ones stay", log.F("version", st.Version))
	}
	s.o.Logger.Info("accessd: rendered from the store", log.F("version", st.Version), log.F("ms", time.Since(started).Milliseconds()))
}

func (s *Server) sshPaths() sshconfig.Paths {
	sp := sshconfig.DefaultPaths()
	sp.ConfigDir = s.o.Paths.SSHDir()
	sp.PidFile = s.o.Paths.SSHDPidFile()
	return sp
}

// renderSSH renders into a new directory, has the pinned sshd check it,
// then swaps it in whole; sshd gets a SIGHUP when sshd_config changed (a
// key file is read at each login, so a key change needs none).
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
	mode := sshconfig.EnrolMode
	if ownerKey(st) {
		mode = sshconfig.AdminMode
	}
	dir := s.o.Paths.SSHDir()
	next, old := dir+".next", dir+".old"
	for _, d := range []string{next, old} {
		if err := os.RemoveAll(d); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(next, 0o755); err != nil { // #nosec G301 -- sshd reads the key files as the logging-in user
		return err
	}
	in := sshconfig.Input{ListenAddrs: listen, Mode: mode, State: st, Paths: s.sshPaths()}
	if err := sshconfig.Render(in, next); err != nil {
		return err
	}
	if s.o.Paths.SSHD != "" {
		if err := sshconfig.Check(s.o.Paths.SSHD, next); err != nil {
			return err
		}
	}
	cfg, err := os.ReadFile(filepath.Join(next, "sshd_config")) // #nosec G304 -- the file just rendered
	if err != nil {
		return err
	}
	prev, perr := os.ReadFile(filepath.Join(dir, "sshd_config")) // #nosec G304 -- the live file accessd rendered
	if _, err := os.Stat(dir); err == nil {
		if err := os.Rename(dir, old); err != nil {
			return err
		}
	}
	if err := os.Rename(next, dir); err != nil {
		return err
	}
	if err := os.RemoveAll(old); err != nil {
		s.o.Logger.Warn("accessd: the previous sshd files weren't removed", log.F("error", err.Error()))
	}
	changed := perr == nil && !bytes.Equal(cfg, prev)
	s.o.Logger.Debug("accessd: sshd files rendered", log.F("mode", string(mode)), log.F("listen", len(listen)), log.F("configChanged", changed))
	if changed {
		s.reloadSSHD()
	}
	return nil
}

func ownerKey(st access.State) bool {
	for _, a := range st.Admins {
		if a.Role == access.RoleOwner && len(a.Keys) > 0 {
			return true
		}
	}
	return false
}

// reloadSSHD sends sshd a SIGHUP, which has it re-read its config; with no
// pid file sshd isn't running and picks the config up when it starts.
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
