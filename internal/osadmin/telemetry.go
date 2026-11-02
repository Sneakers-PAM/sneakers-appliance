// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxsettings"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/edgefall"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productimport"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// TelemetrySettings keep the product's collector settings
// (boxsettings.Store on the box).
type TelemetrySettings interface {
	Telemetry() (boxsettings.Telemetry, error)
	SetTelemetry(boxsettings.Telemetry) error
}

// TelemetryWorkloads restart the workloads that read the telemetry
// settings once k0s has applied them.
type TelemetryWorkloads interface {
	// Applied waits until k0s has applied the box secrets stack as it is
	// on disk now.
	Applied(ctx context.Context) error
	// Restart restarts one workload.
	Restart(ctx context.Context, ns, kind, name string) error
	// RolledOut says why a workload hasn't rolled out yet, or "" once it
	// has; present is false when the cluster doesn't have it.
	RolledOut(ctx context.Context, ns, kind, name string) (why string, present bool, err error)
}

// DefaultTelemetryPhaseBound is how long a phase's workloads may take to
// come back from a restart.
const DefaultTelemetryPhaseBound = productspec.DefaultPhaseTimeout

// telemetryMaintenanceMargin is what a restart's maintenance holds past
// its bounds, for the writes between them.
const telemetryMaintenanceMargin = time.Minute

// telemetryPoll is how often a restart asks about its workloads.
const telemetryPoll = 3 * time.Second

// telemetryRestartFile keeps the last restart on the state volume, so a
// restart a reboot cut off shows on the page with its retry.
const telemetryRestartFile = "telemetry-restart.json"

// telemetryStatusBound bounds the read of the workloads' export states.
const telemetryStatusBound = 5 * time.Second

// The states of a restart.
const (
	telemetryRestartNone    = "none"
	telemetryRestartRunning = "running"
	telemetryRestartDone    = "done"
	telemetryRestartFailed  = "failed"
)

type telemetryRun struct {
	State    string `json:"state"`
	Phase    string `json:"phase,omitempty"`
	Workload string `json:"workload,omitempty"`
	Why      string `json:"why,omitempty"`
}

// telemetryState is the restart this process runs.
type telemetryState struct {
	mu   sync.Mutex
	live bool
}

type telemetrySvc struct {
	osadminv1connect.UnimplementedTelemetryServiceHandler
	s *Server
}

func telemetryToWire(t boxsettings.Telemetry) *osadminv1.TelemetrySettings {
	return &osadminv1.TelemetrySettings{Enabled: t.Enabled, Endpoint: t.Endpoint, SkipVerify: t.SkipVerify, Logs: t.Logs}
}

func telemetryFromWire(w *osadminv1.TelemetrySettings) boxsettings.Telemetry {
	return boxsettings.Telemetry{Enabled: w.GetEnabled(), Endpoint: w.GetEndpoint(), SkipVerify: w.GetSkipVerify(), Logs: w.GetLogs()}
}

// telemetryProduct is the installed product when it reads telemetry
// settings.
func (s *Server) telemetryProduct() (productspec.Spec, error) {
	info, spec := s.installedSpec()
	switch {
	case !info.Present():
		return spec, codes.New(codes.NotAvailable, "no product is installed")
	case !spec.ReadsTelemetry():
		return spec, codes.New(codes.NotAvailable, "%s reads no telemetry settings", info.Title)
	case s.o.Telemetry == nil || s.o.TelemetryWorkloads == nil:
		return spec, codes.New(codes.NotAvailable, "this box keeps no telemetry settings")
	}
	return spec, nil
}

func (s *Server) telemetryRunFile() string {
	return filepath.Join(s.o.Paths.State, "platform", telemetryRestartFile)
}

// readTelemetryRun is the last restart. One the file says runs, with none
// running here, was cut off.
func (s *Server) readTelemetryRun() telemetryRun {
	s.telemetry.mu.Lock()
	defer s.telemetry.mu.Unlock()
	r := telemetryRun{State: telemetryRestartNone}
	b, err := os.ReadFile(s.telemetryRunFile())
	if errors.Is(err, fs.ErrNotExist) {
		return r
	}
	if err == nil {
		err = json.Unmarshal(b, &r)
	}
	if err != nil {
		s.o.Logger.Warn("osadmin: the telemetry restart's record doesn't read", log.F("error", err.Error()))
		return telemetryRun{State: telemetryRestartNone}
	}
	if r.State == telemetryRestartRunning && !s.telemetry.live {
		r.State, r.Why = telemetryRestartFailed, "the restart was cut off"
	}
	return r
}

// writeTelemetryRun keeps r; live says a restart still runs here.
func (s *Server) writeTelemetryRun(r telemetryRun, live bool) {
	s.telemetry.mu.Lock()
	defer s.telemetry.mu.Unlock()
	s.telemetry.live = live
	b, err := json.Marshal(r)
	if err == nil {
		p := s.telemetryRunFile()
		if err = os.MkdirAll(filepath.Dir(p), 0o700); err == nil {
			if err = os.WriteFile(p+".new", append(b, '\n'), 0o600); err == nil {
				err = os.Rename(p+".new", p)
			}
		}
	}
	if err != nil {
		s.o.Logger.Warn("osadmin: the telemetry restart's record wasn't kept", log.F("error", err.Error()))
	}
}

// importRunning says an import step runs: a restart would pull its
// database and services from under it.
func (s *Server) importRunning() bool {
	m, _, _, err := s.importer()
	if err != nil {
		return false
	}
	runs, err := m.Runs()
	if err != nil {
		return false
	}
	return slices.ContainsFunc(runs, func(r productimport.Run) bool { return !r.Done })
}

// telemetryStatus is each workload's export state, through the API server's
// service proxy.
func (s *Server) telemetryStatus(ctx context.Context, spec productspec.Spec) ([]*osadminv1.TelemetryWorkload, string) {
	ns, proxy, ok := spec.Telemetry.StatusRef()
	if !ok || s.o.Exposed == nil {
		return nil, ""
	}
	ctx, cancel := context.WithTimeout(ctx, telemetryStatusBound)
	defer cancel()
	b, err := s.o.Exposed.ServiceGet(ctx, ns, proxy, productspec.TelemetryStatusPath)
	if err != nil {
		s.o.Logger.Debug("osadmin: the services' export states can't be read", log.F("error", err.Error()))
		return nil, "the services' export states can't be read while the gateway is down"
	}
	var out struct {
		Services []struct {
			Name  string `json:"name"`
			State string `json:"state"`
		} `json:"services"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, "the gateway's answer doesn't read"
	}
	w := make([]*osadminv1.TelemetryWorkload, 0, len(out.Services))
	for _, e := range out.Services {
		w = append(w, &osadminv1.TelemetryWorkload{Name: e.Name, State: e.State})
	}
	return w, ""
}

// GetTelemetry is the saved settings, each service's export state and the
// last restart.
func (h *telemetrySvc) GetTelemetry(ctx context.Context, _ *connect.Request[osadminv1.GetTelemetryRequest]) (*connect.Response[osadminv1.GetTelemetryResponse], error) {
	s := h.s
	out := &osadminv1.GetTelemetryResponse{State: "not installed", Settings: &osadminv1.TelemetrySettings{}, Restart: &osadminv1.TelemetryRestart{State: telemetryRestartNone}}
	info, spec := s.installedSpec()
	switch {
	case !info.Present():
		return connect.NewResponse(out), nil
	case !spec.ReadsTelemetry() || s.o.Telemetry == nil:
		out.State = "not in this product"
		return connect.NewResponse(out), nil
	}
	t, err := s.o.Telemetry.Telemetry()
	if err != nil {
		return nil, err
	}
	r := s.readTelemetryRun()
	out.State, out.Settings, out.Label, out.LogsHeld = "off", telemetryToWire(t), spec.Telemetry.Label, t.Enabled && t.Logs && t.SkipVerify
	out.Restart = &osadminv1.TelemetryRestart{State: r.State, Phase: r.Phase, Workload: r.Workload, Why: r.Why}
	if t.Enabled {
		out.State = "on"
	}
	out.Workloads, out.StatusError = s.telemetryStatus(ctx, spec)
	return connect.NewResponse(out), nil
}

// SetTelemetry checks the collector and saves the settings. When what the
// services read changes, it writes the box's stack and restarts them in the
// background, phase by phase, under the maintenance gate; the product isn't
// stopped.
func (h *telemetrySvc) SetTelemetry(ctx context.Context, r *connect.Request[osadminv1.SetTelemetryRequest]) (*connect.Response[osadminv1.SetTelemetryResponse], error) {
	s, c := h.s, callFrom(ctx)
	spec, err := s.telemetryProduct()
	if err != nil {
		return nil, err
	}
	saved, err := s.o.Telemetry.Telemetry()
	if err != nil {
		return nil, err
	}
	t := telemetryFromWire(r.Msg.GetSettings())
	logsOn := t.Enabled && t.Logs && (!saved.Enabled || !saved.Logs)
	c.note("product telemetry", "enabled", onOff(t.Enabled), "endpoint", t.Endpoint, "verify", onOff(!t.SkipVerify), "logs", onOff(t.Logs), "logs_turned_on", strconv.FormatBool(logsOn))
	if err := t.Check(); err != nil {
		return nil, err
	}
	probe := t.Probe
	if s.o.ProbeTelemetry != nil {
		probe = func(ctx context.Context) error { return s.o.ProbeTelemetry(ctx, t) }
	}
	if err := probe(ctx); err != nil {
		return nil, err
	}
	if s.importRunning() {
		return nil, codes.New(codes.UpgradeBusy, "an import step is running; wait for it to finish, then try again")
	}
	if maps.Equal(saved.Values(), t.Values()) {
		if err := s.o.Telemetry.SetTelemetry(t); err != nil {
			return nil, err
		}
		return connect.NewResponse(&osadminv1.SetTelemetryResponse{}), nil
	}
	overrode, err := s.beginMaintenance(ctx, "product telemetry settings apply", edgefall.KindProductApply, c.by("product.telemetry.set"), r.Msg.GetElevationOverride())
	if err != nil {
		return nil, err
	}
	if overrode != "" {
		c.note("product telemetry", "overrode", overrode)
	}
	if err := s.o.Telemetry.SetTelemetry(t); err != nil {
		s.endMaintenance()
		return nil, err
	}
	if s.o.BoxSecrets != nil {
		if err := s.o.BoxSecrets.Ensure(s.slots().Current()); err != nil {
			s.endMaintenance()
			s.o.Logger.Error(err, "osadmin: the telemetry settings didn't reach the box's stack")
			return nil, err
		}
	}
	if t.Enabled && t.SkipVerify {
		s.o.Logger.Warn("osadmin: the product exports to a collector that isn't verified; no logs leave while that's so", log.F("endpoint", t.Endpoint), log.F("by", c.session.Admin))
	}
	if logsOn {
		s.o.Logger.Warn("osadmin: the product's services export logs now", log.F("endpoint", t.Endpoint), log.F("by", c.session.Admin))
	}
	s.o.Logger.Info("osadmin: the telemetry settings are saved; the services restart in order", log.F("enabled", t.Enabled), log.F("endpoint", t.Endpoint), log.F("by", c.session.Admin))
	s.restartTelemetryReaders(spec, "")
	return connect.NewResponse(&osadminv1.SetTelemetryResponse{Restarting: true}), nil
}

// RetryTelemetryRestart carries a failed restart on from the phase it
// stopped at.
func (h *telemetrySvc) RetryTelemetryRestart(ctx context.Context, r *connect.Request[osadminv1.RetryTelemetryRestartRequest]) (*connect.Response[osadminv1.RetryTelemetryRestartResponse], error) {
	s, c := h.s, callFrom(ctx)
	spec, err := s.telemetryProduct()
	if err != nil {
		return nil, err
	}
	run := s.readTelemetryRun()
	c.note("product telemetry", "phase", run.Phase, "workload", run.Workload)
	if run.State != telemetryRestartFailed {
		return nil, codes.New(codes.TelemetryRestart, "no telemetry restart has failed; there's nothing to retry")
	}
	if s.importRunning() {
		return nil, codes.New(codes.UpgradeBusy, "an import step is running; wait for it to finish, then try again")
	}
	overrode, err := s.beginMaintenance(ctx, "product telemetry restart", edgefall.KindProductApply, c.by("product.telemetry.restart"), r.Msg.GetElevationOverride())
	if err != nil {
		return nil, err
	}
	if overrode != "" {
		c.note("product telemetry", "overrode", overrode)
	}
	s.restartTelemetryReaders(spec, run.Phase)
	return connect.NewResponse(&osadminv1.RetryTelemetryRestartResponse{}), nil
}

// restartTelemetryReaders restarts the workloads the product names, a phase
// at a time, from the phase from (the first when empty), in the background,
// and ends the maintenance the caller began. A phase that doesn't come back
// stops the run: later phases keep the old settings until a retry.
func (s *Server) restartTelemetryReaders(spec productspec.Spec, from string) {
	s.writeTelemetryRun(telemetryRun{State: telemetryRestartRunning, Phase: from}, true)
	hold := s.telemetryMaintenance(spec, from)
	s.holdMaintenance(hold)
	s.o.Logger.Debug("osadmin: the telemetry restart holds maintenance", log.F("from", from), log.F("for", hold.String()))
	go func() {
		defer s.endMaintenance()
		end := s.runTelemetryRestart(spec, from)
		s.writeTelemetryRun(end, false)
		if end.State == telemetryRestartFailed {
			s.o.Logger.Error(errors.New(end.Why), "osadmin: the telemetry restart stopped; later phases keep the old settings", log.F("phase", end.Phase), log.F("workload", end.Workload))
			return
		}
		s.o.Logger.Info("osadmin: the services restarted for the telemetry settings")
	}()
}

// telemetryPhaseBound is how long each step of a restart may take.
func (s *Server) telemetryPhaseBound() time.Duration {
	if s.o.TelemetryPhaseBound > 0 {
		return s.o.TelemetryPhaseBound
	}
	return DefaultTelemetryPhaseBound
}

// telemetryGroups are the phases a restart from the phase from runs.
func telemetryGroups(spec productspec.Spec, from string) []productspec.RestartGroup {
	groups := spec.Telemetry.Groups(spec)
	first := slices.IndexFunc(groups, func(g productspec.RestartGroup) bool { return g.Phase == from })
	return groups[max(first, 0):]
}

// telemetryMaintenance is how long a restart from the phase from can run:
// a bound for k0s to apply the settings, one for each phase, and a margin.
func (s *Server) telemetryMaintenance(spec productspec.Spec, from string) time.Duration {
	return time.Duration(len(telemetryGroups(spec, from))+1)*s.telemetryPhaseBound() + telemetryMaintenanceMargin
}

func (s *Server) runTelemetryRestart(spec productspec.Spec, from string) telemetryRun {
	bound := s.telemetryPhaseBound()
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	err := s.o.TelemetryWorkloads.Applied(ctx)
	cancel()
	if err != nil {
		return telemetryRun{State: telemetryRestartFailed, Phase: from, Why: "k0s hasn't applied the settings: " + err.Error()}
	}
	for _, g := range telemetryGroups(spec, from) {
		s.writeTelemetryRun(telemetryRun{State: telemetryRestartRunning, Phase: g.Phase}, true)
		if r := s.restartTelemetryPhase(g, bound); r.State == telemetryRestartFailed {
			return r
		}
	}
	return telemetryRun{State: telemetryRestartDone}
}

// restartTelemetryPhase restarts one phase's workloads, leaving out those
// the cluster doesn't have (a switch-off stack), and waits for them all.
func (s *Server) restartTelemetryPhase(g productspec.RestartGroup, bound time.Duration) telemetryRun {
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	defer cancel()
	w := s.o.TelemetryWorkloads
	failed := func(ref, why string) telemetryRun {
		return telemetryRun{State: telemetryRestartFailed, Phase: g.Phase, Workload: ref, Why: why}
	}
	var running []string
	for _, ref := range g.Restart {
		ns, kind, name, _ := productspec.SplitRestart(ref)
		_, present, err := w.RolledOut(ctx, ns, kind, name)
		if err != nil {
			return failed(ref, err.Error())
		}
		if !present {
			s.o.Logger.Info("osadmin: a workload that reads the telemetry settings isn't there; left out", log.F("workload", ref))
			continue
		}
		if err := w.Restart(ctx, ns, kind, name); err != nil {
			return failed(ref, err.Error())
		}
		running = append(running, ref)
	}
	poll := s.o.TelemetryPoll
	if poll <= 0 {
		poll = telemetryPoll
	}
	for _, ref := range running {
		ns, kind, name, _ := productspec.SplitRestart(ref)
		for {
			why, present, err := w.RolledOut(ctx, ns, kind, name)
			if err == nil && present && why == "" {
				s.o.Logger.Info("osadmin: restarted for the telemetry settings", log.F("workload", ref))
				break
			}
			if err == nil && !present {
				why = "it's gone from the cluster"
			}
			select {
			case <-ctx.Done():
				if err != nil {
					why = err.Error()
				}
				return failed(ref, fmt.Sprintf("it isn't back after %s: %s", bound, why))
			case <-time.After(poll):
			}
		}
	}
	return telemetryRun{State: telemetryRestartDone, Phase: g.Phase}
}
