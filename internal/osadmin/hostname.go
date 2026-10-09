// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// BoxValues are the box's own values the product's stacks read, its FQDN
// first (package boxvalues).
type BoxValues interface {
	// FQDN is the box's FQDN now.
	FQDN(ctx context.Context) (string, error)
	// Recorded is the FQDN the product's stacks were last put in place
	// with.
	Recorded() string
	// Ensure records the FQDN now, and says whether it changed.
	Ensure(ctx context.Context) (string, bool, error)
}

// hostNameRetry is how long the host name follower waits before it looks
// again when an update or an elevated shell holds the product.
const hostNameRetry = time.Minute

// recordBoxValues records the box's values for the stacks a product apply
// or revert puts in place; when netd doesn't answer the recorded ones
// stay, and the product starts with them.
func (s *Server) recordBoxValues(ctx context.Context) {
	if s.o.BoxValues == nil {
		return
	}
	fqdn, changed, err := s.o.BoxValues.Ensure(ctx)
	if err != nil {
		s.o.Logger.Warn("osadmin: the box's FQDN can't be read; the product keeps the recorded one", log.F("fqdn", fqdn), log.F("error", err.Error()))
		return
	}
	s.o.Logger.Info("osadmin: the product's stacks take the box's FQDN", log.F("fqdn", fqdn), log.F("changed", changed))
}

// HostNameChanged follows netd's host name and address events (accessd
// calls it on each, and once at start): when the box's FQDN is no longer
// the one the product's stacks were put in place with, the product is
// applied again with the new one, under the same maintenance gate as an
// update. A change that still waits for its confirm (120 s) is left until
// it is kept, so a reverted name never reaches the product. A product
// whose bundle reads no box values, or a box with no FQDN recorded yet,
// only has the name recorded.
func (s *Server) HostNameChanged(ctx context.Context) {
	if s.o.BoxValues == nil {
		return
	}
	s.hostName.mu.Lock()
	defer s.hostName.mu.Unlock()
	lg := s.o.Logger
	fqdn, err := s.o.BoxValues.FQDN(ctx)
	if err != nil {
		lg.Warn("osadmin: the box's FQDN can't be read; the product keeps the recorded one", log.F("error", err.Error()))
		return
	}
	was := s.o.BoxValues.Recorded()
	if fqdn == was {
		return
	}
	sl := s.slots()
	v := sl.Status().Installed
	// With nothing recorded yet (the product came before box values),
	// k0s-interim put the stacks in place with the kernel's host name; the
	// FQDN is recorded for the next start rather than restarting now.
	if v == "" || was == "" || !readsBoxValues(sl.Current()) {
		if _, _, err := s.o.BoxValues.Ensure(ctx); err != nil {
			lg.Warn("osadmin: the box's FQDN wasn't recorded", log.F("error", err.Error()))
			return
		}
		lg.Info("osadmin: the box's FQDN is recorded for the next product apply", log.F("fqdn", fqdn), log.F("was", was), log.F("product", v))
		return
	}
	if s.o.Network != nil {
		g, err := s.o.Network.Get(ctx, connect.NewRequest(&netdv1.GetRequest{}))
		if err != nil {
			lg.Warn("osadmin: netd doesn't answer; the host name change waits", log.F("error", err.Error()))
			s.lookAgain(hostNameRetry)
			return
		}
		if g.Msg.GetPending() {
			wait := time.Duration(g.Msg.GetSecondsLeft()+1) * time.Second
			lg.Info("osadmin: the host name change waits for its confirm before the product follows", log.F("fqdn", fqdn), log.F("change", g.Msg.GetChangeId()), log.F("wait", wait.String()))
			s.lookAgain(wait)
			return
		}
	}
	if s.Maintenance() {
		lg.Info("osadmin: an update holds the product; the host name change waits", log.F("fqdn", fqdn))
		s.lookAgain(hostNameRetry)
		return
	}
	by := osaudit.Entry{Actor: "box", Action: "upgrade.apply"}
	if _, err := s.beginMaintenance(ctx, "product re-apply for the new host name", by, nil); err != nil {
		lg.Warn("osadmin: the host name change waits", log.F("fqdn", fqdn), log.F("error", err.Error()))
		s.lookAgain(hostNameRetry)
		return
	}
	lg.Info("osadmin: the host name changed; the product is applied again with it", log.F("fqdn", fqdn), log.F("was", was), log.F("version", v))
	s.continueApply(osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT, v, "")
	err = s.switchProduct(ctx, func() error { return nil })
	s.endMaintenance()
	detail := "host name " + fqdn
	s.historyFor(osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT, "apply", v, by.Actor, err, detail)
	s.write(osaudit.Entry{Actor: by.Actor, Action: by.Action, Target: "product", Detail: map[string]string{"version": v, "surface": "hostname", "hostname": fqdn, "was": was}}, err)
	if err != nil {
		lg.Error(err, "osadmin: the product wasn't applied again for the new host name", log.F("fqdn", fqdn))
	}
}

// lookAgain runs the follower again after d; a later call replaces an
// earlier one. The caller holds hostName.mu.
func (s *Server) lookAgain(d time.Duration) {
	if s.hostName.timer != nil {
		s.hostName.timer.Stop()
	}
	s.hostName.timer = s.o.Clock.AfterFunc(d, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		s.HostNameChanged(ctx)
	})
}

// readsBoxValues reports whether the slot's bundle declares box values.
func readsBoxValues(slot string) bool {
	if slot == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(slot, productspec.BoxValuesFile))
	return err == nil
}
