// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package wizard

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

// Deps are what the wizard reads and drives.
type Deps struct {
	Chrome   consoleui.Chrome
	Custody  func(ctx context.Context) (keycustody.Protection, keycustody.Mode, error)
	Network  sources.Network
	Services sources.Services
	Access   accessv1connect.AccessServiceClient
	Setup    accessv1connect.SetupServiceClient
	Status   func(ctx context.Context) sources.StatusView
	Steps    Steps
	Power    initv1connect.PowerServiceClient
	Logger   log.Logger
}

type run struct {
	u    *tui.UI
	d    Deps
	f    Frame
	sshd error
}

// Run runs first boot on the console until setup is complete, then keeps
// the last screen.
func Run(ctx context.Context, u *tui.UI, d Deps) error {
	if d.Logger == nil {
		d.Logger = log.Nop()
	}
	r := &run{u: u, d: d, f: Frame{Chrome: d.Chrome}}
	if p, m, err := d.Custody(ctx); err == nil {
		r.f.Chrome.Protection, r.f.Chrome.Mode, r.f.Chrome.Known = p, m, true
	} else {
		d.Logger.Warn("wizard: init's custody didn't answer", log.F("error", err.Error()))
	}
	for {
		step, err := r.next(ctx)
		if err != nil {
			d.Logger.Warn("wizard: the progress can't be read", log.F("error", err.Error()))
			if _, _, aerr := u.Ask(ctx, tui.Static(r.f.Page(errLines("The appliance services aren't answering: "+consoleui.Describe(err)), "Enter: try again", "> "))); aerr != nil {
				return aerr
			}
			continue
		}
		r.f.Step = step
		d.Logger.Info("wizard: step", log.F("step", int(step)))
		switch step {
		case StepNetwork:
			err = r.network(ctx)
		case StepProtection:
			_, _, err = u.Ask(ctx, tui.Static(ProtectionPage(r.f, r.f.Chrome.Protection, r.f.Chrome.Mode)))
		case StepAdmin:
			// The first admin is made on the :8443 setup page.
		case StepRecovery, StepSignIn, StepDone:
			err = r.continueOn(ctx)
		default:
			return r.complete(ctx)
		}
		if err != nil {
			return err
		}
		if step <= StepAdmin {
			if err := d.Steps.Complete(ctx, step); err != nil {
				return err
			}
		}
	}
}

// next is the first step not done (0 once every one is), and fills the
// step strip.
func (r *run) next(ctx context.Context) (Step, error) {
	done := make([]bool, 0, 5)
	first := Step(0)
	for s := StepNetwork; s <= StepDone; s++ {
		ok, err := r.d.Steps.Done(ctx, s)
		if err != nil {
			return 0, err
		}
		if s <= StepSignIn {
			done = append(done, ok)
		}
		if !ok && first == 0 {
			first = s
		}
	}
	r.f.Done = done
	return first, nil
}

// network is step 1: the interface, the settings, apply and check.
func (r *run) network(ctx context.Context) error {
	if r.d.Network.Installed() {
		kept, err := r.current(ctx)
		if err != nil || kept {
			return err
		}
	}
	nics, err := r.d.Network.Interfaces(ctx)
	errLine := ""
	if err != nil {
		errLine = "The interfaces can't be listed: " + err.Error()
	}
	mgmt, err := r.pickNIC(ctx, nics, false, "", errLine)
	if err != nil {
		return err
	}
	form := Form{S: network.Defaults(mgmt.Name)}
	if len(nics) > 1 {
		svc, err := r.pickNIC(ctx, nics, true, mgmt.Name, "")
		if err != nil {
			return err
		}
		if svc.Name != "" && svc.Name != mgmt.Name {
			i := network.Interface{Name: svc.Name, IPv4: network.Family4{Mode: network.V4DHCP}, IPv6: network.Family6{Mode: network.V6SLAAC}}
			form.S.Service = &i
		}
	}
	if cur, err := r.d.Network.Get(ctx); err == nil && cur.Management.Name == mgmt.Name {
		form.S = cur
	}
	errLine = ""
	for {
		line, _, err := r.u.Ask(ctx, tui.Static(SettingsPage(r.f, form, errLine)))
		if err != nil {
			return err
		}
		errLine = ""
		if n, convErr := strconv.Atoi(strings.TrimSpace(line)); convErr == nil {
			if err := r.editField(ctx, &form, n); err != nil {
				return err
			}
			continue
		}
		if strings.TrimSpace(line) != "" {
			errLine = "Type 1 to 5 to change a setting, or press Enter to apply."
			continue
		}
		if err := network.Validate(form.S); err != nil {
			errLine = consoleui.Describe(err)
			continue
		}
		done, err := r.apply(ctx, form)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
}

func (r *run) pickNIC(ctx context.Context, nics []sources.NIC, service bool, mgmt, errLine string) (sources.NIC, error) {
	for {
		line, _, err := r.u.Ask(ctx, tui.Static(NICsPage(r.f, nics, service, mgmt, errLine)))
		if err != nil {
			return sources.NIC{}, err
		}
		errLine = ""
		if NoLink(nics) {
			if fresh, err := r.d.Network.Interfaces(ctx); err == nil {
				nics = fresh
			}
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			if service {
				return sources.NIC{}, nil
			}
			return nics[0], nil
		}
		i, err := strconv.Atoi(line)
		if err != nil || i < 1 || i > len(nics) {
			errLine = fmt.Sprintf("Type a number from 1 to %d.", len(nics))
			continue
		}
		return nics[i-1], nil
	}
}

// editField reads one field's new value into form.
func (r *run) editField(ctx context.Context, form *Form, n int) error {
	if _, ok := FieldHelp[n]; !ok {
		return nil
	}
	errLine := ""
	for {
		line, _, err := r.u.Ask(ctx, tui.Static(FieldPage(r.f, n, errLine)))
		if err != nil {
			return err
		}
		if err := setField(&form.S, n, line); err != nil {
			errLine = err.Error()
			continue
		}
		return nil
	}
}

// setField parses one field's value.
func setField(s *network.Settings, n int, line string) error {
	words := strings.Fields(strings.ToLower(line))
	switch n {
	case 1:
		if len(words) == 0 {
			return errors.New("type dhcp, off or static <address/prefix> <gateway>")
		}
		switch words[0] {
		case "dhcp":
			s.Management.IPv4 = network.Family4{Mode: network.V4DHCP}
		case "off":
			s.Management.IPv4 = network.Family4{Mode: network.V4Off}
		case "static":
			p, gw, err := static(words[1:])
			if err != nil || !p.Addr().Is4() {
				return errors.New("type static, the IPv4 address with its prefix, and the gateway: static 192.0.2.10/24 192.0.2.1")
			}
			s.Management.IPv4 = network.Family4{Mode: network.V4Static, Address: p, Gateway: gw}
		default:
			return errors.New("type dhcp, off or static <address/prefix> <gateway>")
		}
	case 2:
		if len(words) == 0 {
			return errors.New("type slaac, dhcpv6, off or static <address/prefix> <gateway>")
		}
		switch words[0] {
		case "slaac":
			s.Management.IPv6 = network.Family6{Mode: network.V6SLAAC}
		case "dhcpv6":
			s.Management.IPv6 = network.Family6{Mode: network.V6DHCPv6}
		case "off":
			s.Management.IPv6 = network.Family6{Mode: network.V6Off}
		case "static":
			p, gw, err := static(words[1:])
			if err != nil || !p.Addr().Is6() {
				return errors.New("type static, the IPv6 address with its prefix, and the gateway: static 2001:db8::10/64 2001:db8::1")
			}
			s.Management.IPv6 = network.Family6{Mode: network.V6Static, Address: p, Gateway: gw}
		default:
			return errors.New("type slaac, dhcpv6, off or static <address/prefix> <gateway>")
		}
	case 3:
		if len(words) == 0 {
			s.Hostname = ""
			return nil
		}
		if !network.ValidHostname(words[0]) || len(words) > 1 {
			return fmt.Errorf("%q isn't a fully qualified host name, such as appliance.example.org", line)
		}
		s.Hostname = words[0]
	case 4:
		if len(words) > network.MaxDNS {
			return fmt.Errorf("at most %d DNS servers", network.MaxDNS)
		}
		var dns []netip.Addr
		for _, w := range words {
			a, err := netip.ParseAddr(w)
			if err != nil {
				return fmt.Errorf("%q isn't an IPv4 or IPv6 address", w)
			}
			dns = append(dns, a)
		}
		s.DNS = dns
	case 5:
		if len(words) > network.MaxNTP {
			return fmt.Errorf("at most %d NTP servers", network.MaxNTP)
		}
		s.NTP = words
	}
	return nil
}

func static(words []string) (netip.Prefix, netip.Addr, error) {
	if len(words) < 1 || len(words) > 2 {
		return netip.Prefix{}, netip.Addr{}, errors.New("static takes an address/prefix and a gateway")
	}
	p, err := netip.ParsePrefix(words[0])
	if err != nil {
		return netip.Prefix{}, netip.Addr{}, err
	}
	var gw netip.Addr
	if len(words) == 2 {
		if gw, err = netip.ParseAddr(words[1]); err != nil {
			return netip.Prefix{}, netip.Addr{}, err
		}
	}
	return p, gw, nil
}

// apply sets form live and runs the checks; done reports the step is
// finished (the change kept).
func (r *run) apply(ctx context.Context, form Form) (bool, error) {
	token, revert, err := r.d.Network.Set(ctx, form.S)
	for sources.IsNotInstalled(err) {
		r.d.Logger.Warn("wizard: the network can't be applied; netd isn't installed")
		line, _, aerr := r.u.Ask(ctx, tui.Static(NotInstalledPage(r.f, err)))
		if aerr != nil {
			return false, aerr
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "e":
			return false, nil
		case "r":
			token, revert, err = r.d.Network.Set(ctx, form.S)
		}
	}
	if err != nil {
		_, _, aerr := r.u.Ask(ctx, tui.Static(SettingsPage(r.f, form, "The settings weren't applied: "+consoleui.Describe(err))))
		return false, aerr
	}
	r.d.Logger.Info("wizard: network applied; checking", log.F("revert_after", revert))
	return r.checks(ctx, token, revert)
}

// current is the network netd set up by itself on its first start (DHCP
// and SLAAC on the first linked NIC): its address, kept with Enter after
// the checks, or e to choose the interface and settings. kept reports the
// step done.
func (r *run) current(ctx context.Context) (bool, error) {
	for {
		var a sources.Addresses
		var aerr error
		line, _, err := r.u.Ask(ctx, func() (tui.Page, bool) {
			a, aerr = r.d.Network.Status(ctx)
			return CurrentPage(r.f, a, aerr), false
		})
		if err != nil {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "e":
			return false, nil
		case "":
			if aerr != nil || len(hostsOf(a.Management)) == 0 {
				continue
			}
			kept, err := r.checks(ctx, "", 0)
			if err != nil || kept {
				return kept, err
			}
		}
	}
}

// checks runs netd's checks until they settle and shows them; a failed
// one can be skipped (c), but no address can't. With token the change is
// confirmed when kept. kept reports the step done; false is e (edit).
func (r *run) checks(ctx context.Context, token string, revert int) (bool, error) {
	var checks []sources.Check
	var checkErr string
	settled := false
	for {
		line, typed, err := r.u.Ask(ctx, func() (tui.Page, bool) {
			if !settled {
				cs, err := r.d.Network.Checks(ctx)
				if err != nil {
					checkErr = consoleui.Describe(err)
				} else {
					checks, checkErr = cs, ""
					settled = len(cs) > 0
					for _, c := range cs {
						if c.State == sources.CheckRunning {
							settled = false
						}
					}
				}
			}
			return ChecksPage(r.f, checks, revert, checkErr), false
		})
		if err != nil {
			return false, err
		}
		if !typed || !settled {
			continue
		}
		failed, blocked := false, false
		for _, c := range checks {
			if c.State == sources.CheckFailed {
				failed = true
				blocked = blocked || !c.Skippable
			}
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "e":
			return false, nil
		case "c":
			if blocked || !failed {
				continue
			}
		case "":
			if failed {
				continue
			}
		default:
			continue
		}
		if token != "" {
			if err := r.d.Network.Confirm(ctx, token); err != nil {
				checkErr = "The change couldn't be kept: " + consoleui.Describe(err)
				continue
			}
		}
		r.d.Logger.Info("wizard: network kept", log.F("checks_failed", failed))
		return true, nil
	}
}

// addresses are the management addresses for the screens.
func (r *run) addresses(ctx context.Context) ([]string, error) {
	a, err := r.d.Network.Status(ctx)
	return a.Management, err
}

// continueOn is the rest of setup: :8443 runs (accessd starts sshd once
// the first admin exists), the screen follows the recovery keys and
// the first sign-in, then setup completes: the single-admin warning
// confirmed if it applies, and accessd's Complete, which checks every step
// and writes setup/done.
func (r *run) continueOn(ctx context.Context) error {
	if err := r.d.Network.SetManagementPorts(ctx, true, true); err != nil {
		r.d.Logger.Warn("wizard: ports 22 and 8443 didn't open", log.F("error", err.Error()))
	}
	osErr := r.d.Services.Start(ctx, "osadmin")
	if osErr != nil {
		r.d.Logger.Warn("wizard: osadmin didn't start", log.F("error", osErr.Error()))
	}
	owner := ""
	if l, err := r.d.Access.ListAdmins(ctx, connect.NewRequest(&accessv1.ListAdminsRequest{})); err == nil {
		for _, a := range l.Msg.GetAdmins() {
			if a.GetRole() == osadminv1.Role_ROLE_OWNER && owner == "" {
				owner = a.GetName()
			}
		}
	}
	last := time.Time{}
	var c Continue
	var state *osadminv1.GetSetupResponse
	for {
		_, _, err := r.u.Ask(ctx, func() (tui.Page, bool) {
			if time.Since(last) < time.Second {
				return ContinuePage(r.f, c), false
			}
			last = time.Now()
			c = Continue{OsadminErr: osErr, Max: int32(access.MaxRecoveryKeys), Admin: owner, Err: c.Err}
			c.Addresses, c.AddrErr = r.addresses(ctx)
			if st := r.d.Status(ctx); st.Status != nil {
				c.TLS = st.Status.GetTlsFingerprint()
			}
			if ci, err := r.d.Setup.GetConsoleInfo(ctx, connect.NewRequest(&accessv1.GetConsoleInfoRequest{})); err == nil {
				c.SetupCode = ci.Msg.GetConsoleInfo().GetSetupCode()
			}
			s, err := r.d.Setup.GetSetup(ctx, connect.NewRequest(&accessv1.GetSetupRequest{}))
			if err != nil {
				return ContinuePage(r.f, c), false
			}
			state = s.Msg.GetSetup()
			c.Recovery = state.GetRecoveryKeys()
			if r.progress(ctx, state) {
				return tui.Page{}, true
			}
			return ContinuePage(r.f, c), false
		})
		if err != nil {
			return err
		}
		if done, err := r.d.Steps.Done(ctx, StepDone); err == nil && done {
			return nil
		}
		if signed, _ := r.d.Steps.Done(ctx, StepSignIn); !signed || state == nil {
			continue
		}
		if state.GetSingleAdminWarning() && !state.GetSingleAdminAcknowledged() {
			if err := r.singleAdmin(ctx); err != nil {
				return err
			}
			continue
		}
		if _, err := r.d.Setup.Complete(ctx, connect.NewRequest(&accessv1.CompleteRequest{})); err != nil {
			c.Err = "Setup can't complete yet: " + consoleui.Describe(err)
			r.d.Logger.Warn("wizard: Setup.Complete refused", log.F("error", consoleui.Describe(err)))
			continue
		}
		r.d.Logger.Info("wizard: setup complete")
		return r.d.Steps.Complete(ctx, StepDone)
	}
}

// progress completes the recovery and sign-in steps as the box shows them
// done, and reports whether the wait is over (sign-in done, or setup
// finished from :8443).
func (r *run) progress(ctx context.Context, s *osadminv1.GetSetupResponse) bool {
	step := func(st Step) bool { ok, _ := r.d.Steps.Done(ctx, st); return ok }
	if !step(StepRecovery) && len(s.GetRecoveryKeys()) > 0 {
		if err := r.d.Steps.Complete(ctx, StepRecovery); err != nil {
			r.d.Logger.Warn("wizard: the recovery step didn't complete", log.F("error", err.Error()))
		}
	}
	if step(StepRecovery) && !step(StepSignIn) && s.GetSignedIn() {
		if err := r.d.Steps.Complete(ctx, StepSignIn); err != nil {
			r.d.Logger.Warn("wizard: the sign-in step didn't complete", log.F("error", err.Error()))
		}
	}
	r.f.Done[StepRecovery-1], r.f.Done[StepSignIn-1] = step(StepRecovery), step(StepSignIn)
	if s.GetDone() && step(StepSignIn) && !step(StepDone) {
		if err := r.d.Steps.Complete(ctx, StepDone); err != nil {
			r.d.Logger.Warn("wizard: the done step didn't complete", log.F("error", err.Error()))
		}
	}
	return step(StepSignIn)
}

// singleAdmin asks the operator to confirm going on with one admin.
func (r *run) singleAdmin(ctx context.Context) error {
	errLine := ""
	for {
		line, _, err := r.u.Ask(ctx, tui.Static(SingleAdminPage(r.f, errLine)))
		if err != nil {
			return err
		}
		if strings.TrimSpace(line) != TypedOneAdmin {
			errLine = "Type " + TypedOneAdmin + " to go on with one admin, or add a second admin on :8443 first."
			continue
		}
		if _, err := r.d.Setup.AcknowledgeSingleAdmin(ctx, connect.NewRequest(&accessv1.AcknowledgeSingleAdminRequest{})); err != nil {
			errLine = consoleui.Describe(err)
			continue
		}
		r.d.Logger.Info("wizard: the single-admin warning was confirmed on the console")
		return nil
	}
}

// complete is the last screen: the move to normal, or a restart when that
// isn't installed yet.
func (r *run) complete(ctx context.Context) error {
	c := Complete{}
	if s, err := r.d.Setup.GetSetup(ctx, connect.NewRequest(&accessv1.GetSetupRequest{})); err == nil {
		c.ProductURL = s.Msg.GetSetup().GetProductSetupUrl()
	}
	r.u.Show(CompletePage(r.f, Complete{Starting: true, ProductURL: c.ProductURL}))
	if err := r.d.Steps.Handover(ctx); err != nil {
		c.HandoverErr = err
		r.d.Logger.Info("wizard: setup done; a restart starts normal operation", log.F("why", err.Error()))
	} else {
		c.Ready = true
	}
	for {
		line, _, err := r.u.Ask(ctx, tui.Static(CompletePage(r.f, c)))
		if err != nil {
			return err
		}
		if c.Ready || strings.TrimSpace(line) != "reboot" {
			continue
		}
		if _, err := r.d.Power.Reboot(ctx, connect.NewRequest(&initv1.RebootRequest{})); err != nil {
			c.Err = "The restart was refused: " + consoleui.Describe(err)
		}
	}
}
