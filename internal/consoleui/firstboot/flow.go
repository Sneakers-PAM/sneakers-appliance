// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package firstboot

import (
	"context"
	"strings"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/netedit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/setup"
)

// DefaultDHCPWait is how long first boot waits for a DHCP address before
// it offers to set one by hand.
const DefaultDHCPWait = 30 * time.Second

// Steps is first boot's progress (internal/setup's step machine) and the
// move to normal operation at the end.
type Steps interface {
	Done(s setup.Step) bool
	Complete(s setup.Step) error
	// Handover moves the box to normal operation without a restart.
	Handover(ctx context.Context) error
}

// MachineSteps is the step machine, kept in its progress file so a power
// cut resumes at the first step not done.
type MachineSteps struct{ M *setup.Machine }

// Done reports whether s is done.
func (m MachineSteps) Done(s setup.Step) bool { return m.M.Done(s) }

// Complete marks s done, in order.
func (m MachineSteps) Complete(s setup.Step) error { return m.M.Complete(s) }

// Handover answers NotInstalled: until init can move to normal while it
// runs, the box starts normal operation on a restart.
func (MachineSteps) Handover(context.Context) error {
	return sources.NotInstalled{What: "Moving to normal operation without a restart"}
}

// Setup is the part of accessd's SetupService first boot uses.
type Setup interface {
	GetSetup(ctx context.Context, r *connect.Request[accessv1.GetSetupRequest]) (*connect.Response[accessv1.GetSetupResponse], error)
	Complete(ctx context.Context, r *connect.Request[accessv1.CompleteRequest]) (*connect.Response[accessv1.CompleteResponse], error)
}

// Deps are what first boot reads and drives.
type Deps struct {
	Chrome   consoleui.Chrome
	Custody  func(ctx context.Context) (keycustody.Protection, keycustody.Mode, error)
	Network  sources.Network
	Services sources.Services
	Console  sources.ConsoleAccess
	// Setup is accessd's setup state and its Complete, which first boot
	// calls once the :8443 steps are done.
	Setup Setup
	Steps Steps
	Power initv1connect.PowerServiceClient
	// DHCPWait is how long to wait for DHCP; zero is DefaultDHCPWait.
	DHCPWait time.Duration
	// RestartAfter is how long the done screen shows before the restart.
	RestartAfter time.Duration
	Now          func() time.Time
	Logger       log.Logger
}

type run struct {
	u *tui.UI
	d Deps
	c consoleui.Chrome
}

// Run runs first boot until setup is done and the box moves to normal
// operation.
func Run(ctx context.Context, u *tui.UI, d Deps) error {
	if d.Logger == nil {
		d.Logger = log.Nop()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.DHCPWait == 0 {
		d.DHCPWait = DefaultDHCPWait
	}
	if d.RestartAfter == 0 {
		d.RestartAfter = 5 * time.Second
	}
	r := &run{u: u, d: d, c: d.Chrome}
	r.custody(ctx)
	for {
		var err error
		switch next := r.next(); next {
		case setup.StepNetwork:
			err = r.network(ctx)
		case setup.StepProtection:
			// Chosen at boot from the hardware: shown, never asked.
			err = r.complete(setup.StepProtection)
		case "":
			return r.finish(ctx)
		default:
			err = r.setup(ctx)
		}
		if err != nil {
			return err
		}
	}
}

func (r *run) custody(ctx context.Context) {
	if r.c.Known {
		return
	}
	if p, m, err := r.d.Custody(ctx); err == nil {
		r.c.Protection, r.c.Mode, r.c.Known = p, m, true
	} else {
		r.d.Logger.Warn("firstboot: init's custody didn't answer", log.F("error", err.Error()))
	}
}

func (r *run) next() setup.Step {
	for _, s := range setup.Order {
		if !r.d.Steps.Done(s) {
			return s
		}
	}
	return ""
}

func (r *run) complete(s setup.Step) error {
	if r.d.Steps.Done(s) {
		return nil
	}
	if err := r.d.Steps.Complete(s); err != nil {
		return err
	}
	r.d.Logger.Info("firstboot: step done", log.F("step", string(s)))
	return nil
}

func (r *run) items(network string, took time.Duration) []Item {
	disk := Item{Name: "encrypted data disk", State: "busy"}
	if r.c.Known {
		disk.State = "ok"
	}
	return []Item{
		{Name: "system image verified", State: "ok"},
		disk,
		{Name: "network", State: network, Took: took},
		{Name: "setup page"},
	}
}

// network waits for a DHCP address; when none comes, it offers the editor.
func (r *run) network(ctx context.Context) error {
	if !r.d.Network.Installed() {
		r.d.Logger.Warn("firstboot: no network service in this build; the network step is skipped")
		return r.complete(setup.StepNetwork)
	}
	start := r.d.Now()
	var nics []sources.NIC
	var nicsRead time.Time
	asking := false
	for {
		got := false
		line, typed, err := r.u.Ask(ctx, func() (tui.Page, bool) {
			r.custody(ctx)
			if a, err := r.d.Network.Status(ctx); err == nil && len(sources.Hosts(a.Management)) > 0 {
				got = true
				return tui.Page{}, true
			}
			took := r.d.Now().Sub(start)
			asking = took >= r.d.DHCPWait
			if !asking {
				return StartingPage(r.c, r.items("busy", took)), false
			}
			if time.Since(nicsRead) > 3*time.Second {
				nics, _ = r.d.Network.Interfaces(ctx)
				nicsRead = time.Now()
			}
			return netedit.NoAddressPage(r.c, nics, ""), false
		})
		if err != nil {
			return err
		}
		if got {
			r.d.Logger.Info("firstboot: the network has an address")
			return r.complete(setup.StepNetwork)
		}
		if !typed || !asking {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "n":
			kept, err := netedit.Edit(ctx, r.u, netedit.Deps{Chrome: r.c, Network: r.d.Network, Logger: r.d.Logger})
			if err != nil {
				return err
			}
			if kept {
				return r.complete(setup.StepNetwork)
			}
		case "r":
			r.d.Logger.Info("firstboot: waiting for DHCP again")
			start = r.d.Now()
		}
	}
}

// setup opens :8443, shows the address, the certificate and the setup
// code, and follows the browser's setup until it's done. Steps the backend
// reports done that the step machine still has open are marked here too.
func (r *run) setup(ctx context.Context) error {
	ssh := false
	open := func() {
		if err := r.d.Network.SetManagementPorts(ctx, ssh, true); err != nil && !sources.IsNotInstalled(err) {
			r.d.Logger.Warn("firstboot: the management ports didn't open", log.F("error", err.Error()), log.F("ssh", ssh))
		}
	}
	open()
	if err := r.d.Services.Start(ctx, "osadmin"); err != nil {
		r.d.Logger.Warn("firstboot: the setup page didn't start", log.F("error", err.Error()))
	}
	errLine := ""
	var info sources.ConsoleInfo
	for {
		done := false
		line, typed, err := r.u.Ask(ctx, func() (tui.Page, bool) {
			r.custody(ctx)
			i, err := r.d.Console.Read(ctx)
			if err != nil {
				r.d.Logger.Warn("firstboot: the access service didn't answer", log.F("error", err.Error()))
				return InfoPage(r.c, info, r.d.Now(), "The access service isn't answering yet: "+consoleui.Describe(err)), false
			}
			info = i
			if info.FirstAdmin != "" && !ssh {
				ssh = true
				open()
				if err := r.d.Services.Start(ctx, "sshd"); err != nil {
					r.d.Logger.Warn("firstboot: sshd didn't start", log.F("error", err.Error()))
				}
				if err := r.complete(setup.StepAdmin); err != nil {
					r.d.Logger.Warn("firstboot: the admin step", log.F("error", err.Error()))
				}
			}
			r.follow(ctx)
			if info.State == sources.SetupDone {
				for _, s := range []setup.Step{setup.StepAdmin, setup.StepRecovery, setup.StepSignIn, setup.StepDone} {
					if err := r.complete(s); err != nil {
						r.d.Logger.Warn("firstboot: a step didn't complete", log.F("step", string(s)), log.F("error", err.Error()))
					}
				}
			}
			if r.next() == "" {
				done = true
				return tui.Page{}, true
			}
			if info.State == sources.SetupInProgress {
				return SettingUpPage(r.c, info, errLine), false
			}
			return InfoPage(r.c, info, r.d.Now(), errLine), false
		})
		if err != nil {
			return err
		}
		if done {
			r.d.Logger.Info("firstboot: setup is done")
			return nil
		}
		if typed && strings.EqualFold(strings.TrimSpace(line), "n") && info.CodeLocked {
			errLine = ""
			if err := r.d.Console.ResetSetupCode(ctx); err != nil {
				errLine = "No new code was made: " + consoleui.Describe(err)
			} else {
				r.d.Logger.Info("firstboot: a locked setup code was replaced on the console")
			}
			continue
		}
		if typed && strings.EqualFold(strings.TrimSpace(line), "x") && info.State == sources.SetupInProgress && info.FirstAdmin == "" {
			errLine = ""
			if err := r.d.Console.ResetSetupCode(ctx); err != nil {
				errLine = "The setup wasn't stopped: " + consoleui.Describe(err)
			} else {
				r.d.Logger.Info("firstboot: the browser setup was stopped on the console; a new code is shown")
			}
		}
	}
}

// follow marks the steps :8443 has finished, as accessd's setup state
// shows them (a recovery key, then the first sign-in), and once they're
// done (and a single admin confirmed on the page) asks accessd to complete
// setup, which checks every step again and writes setup/done.
func (r *run) follow(ctx context.Context) {
	if r.d.Setup == nil || !r.d.Steps.Done(setup.StepAdmin) || r.d.Steps.Done(setup.StepDone) {
		return
	}
	res, err := r.d.Setup.GetSetup(ctx, connect.NewRequest(&accessv1.GetSetupRequest{}))
	if err != nil {
		r.d.Logger.Warn("firstboot: accessd's setup state didn't answer", log.F("error", err.Error()))
		return
	}
	s := res.Msg.GetSetup()
	if !r.d.Steps.Done(setup.StepRecovery) && len(s.GetRecoveryKeys()) > 0 {
		if err := r.complete(setup.StepRecovery); err != nil {
			r.d.Logger.Warn("firstboot: the recovery step", log.F("error", err.Error()))
		}
	}
	if r.d.Steps.Done(setup.StepRecovery) && !r.d.Steps.Done(setup.StepSignIn) && s.GetSignedIn() {
		if err := r.complete(setup.StepSignIn); err != nil {
			r.d.Logger.Warn("firstboot: the sign-in step", log.F("error", err.Error()))
		}
	}
	if !r.d.Steps.Done(setup.StepSignIn) || (s.GetSingleAdminWarning() && !s.GetSingleAdminAcknowledged()) {
		return
	}
	if !s.GetDone() {
		if _, err := r.d.Setup.Complete(ctx, connect.NewRequest(&accessv1.CompleteRequest{})); err != nil {
			r.d.Logger.Warn("firstboot: Setup.Complete refused", log.F("error", consoleui.Describe(err)))
			return
		}
		r.d.Logger.Info("firstboot: setup complete")
	}
	if err := r.complete(setup.StepDone); err != nil {
		r.d.Logger.Warn("firstboot: the done step", log.F("error", err.Error()))
	}
}

// finish moves the box to normal operation: at once when init can, by a
// restart otherwise.
func (r *run) finish(ctx context.Context) error {
	r.u.Show(FinishPage(r.c, false, ""))
	err := r.d.Steps.Handover(ctx)
	if err == nil {
		<-ctx.Done()
		return nil
	}
	r.d.Logger.Info("firstboot: setup done; restarting into normal operation", log.F("why", err.Error()))
	r.u.Show(FinishPage(r.c, true, ""))
	wait := r.d.RestartAfter
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		if _, err := r.d.Power.Reboot(ctx, connect.NewRequest(&initv1.RebootRequest{})); err != nil {
			r.d.Logger.Warn("firstboot: the restart was refused", log.F("error", err.Error()))
			r.u.Show(FinishPage(r.c, true, "The restart was refused: "+consoleui.Describe(err)+". It's tried again in 30 seconds."))
			wait = 30 * time.Second
			continue
		}
		<-ctx.Done()
		return nil
	}
}
