// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package dashboard

import (
	"context"
	"strings"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/netedit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
)

// Deps are what the dashboard reads and drives.
type Deps struct {
	Chrome   consoleui.Chrome
	Custody  func(ctx context.Context) (keycustody.Protection, keycustody.Mode, error)
	Status   func(ctx context.Context) sources.StatusView
	Network  sources.Network
	HostKeys func() []sources.HostKey
	Slot     string
	Upgrades sources.Upgrades
	Platform sources.Platform
	// Console is the access backend: Recover access by code.
	Console sources.ConsoleAccess
	// AccessNet resets who can connect, for Recover access.
	AccessNet accessv1connect.NetworkServiceClient
	Local     osadminv1connect.LocalServiceClient
	// Refresh is how often the status is read again; zero is 5 seconds.
	Refresh time.Duration
	Now     func() time.Time
	Logger  log.Logger
}

type console struct {
	u      *tui.UI
	d      Deps
	c      consoleui.Chrome
	data   Data
	loaded time.Time
}

// Run runs the console until ctx ends or the console's input does.
func Run(ctx context.Context, u *tui.UI, d Deps) error {
	if d.Refresh == 0 {
		d.Refresh = 5 * time.Second
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Logger == nil {
		d.Logger = log.Nop()
	}
	k := &console{u: u, d: d, c: d.Chrome}
	k.load(ctx)
	for {
		line, _, err := u.Ask(ctx, k.statusView(ctx))
		if err != nil {
			return err
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "r":
			err = k.recoverAccess(ctx)
		case "n":
			if !HasAddress(k.data) && !sources.IsNotInstalled(k.data.NetErr) {
				_, err = netedit.Edit(ctx, u, netedit.Deps{Chrome: k.c, Network: d.Network, Logger: d.Logger})
			}
		case "c":
			k.cancelReset(ctx)
		}
		if err != nil {
			return err
		}
		k.load(ctx)
	}
}

// load reads everything the status view shows.
func (k *console) load(ctx context.Context) {
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	d := Data{Slot: k.d.Slot}
	if p, m, err := k.d.Custody(c); err == nil {
		k.c.Protection, k.c.Mode, k.c.Known = p, m, true
	} else {
		k.c.Known = false
		k.d.Logger.Warn("console: init's custody didn't answer", log.F("error", err.Error()))
	}
	d.Status = k.d.Status(c)
	if !k.d.Network.Installed() {
		d.NetErr = sources.NotInstalled{What: "The network service"}
	}
	k.c.NTP = consoleui.NTPUnknown
	if st := d.Status.Status; st != nil {
		k.c.Host = st.GetHostname()
		if d.NetErr == nil {
			k.c.NTP = consoleui.NTPUnsynced
			if st.GetNtpSynced() {
				k.c.NTP = consoleui.NTPSynced
			}
		}
	}
	d.HostKeys = k.d.HostKeys()
	d.Upgrade, d.UpgradeErr = k.d.Upgrades.Current(c)
	d.Platform, d.PlatformErr = k.d.Platform.State(c)
	if info, err := k.d.Console.Read(c); err == nil {
		d.Recover = info.Recover
	}
	header := &k.c
	header.Info = Info(d)
	k.data, k.loaded = d, time.Now()
}

// statusView redraws on every tick (the clock and a reset's countdown)
// and reads the status again every Refresh.
func (k *console) statusView(ctx context.Context) func() (tui.Page, bool) {
	return func() (tui.Page, bool) {
		if time.Since(k.loaded) >= k.d.Refresh {
			k.load(ctx)
		}
		if k.data.Upgrade.InProgress || (k.data.UpgradeErr == nil && k.data.Upgrade.Failed != "") {
			return MaintenancePage(k.c, k.data.Upgrade), false
		}
		return Page(k.c, k.data, k.d.Now()), false
	}
}

// recoverAccess is the break-glass screen: reset who can connect, or a
// one-time code that resets an owner's sign-in on :8443.
func (k *console) recoverAccess(ctx context.Context) error {
	errLine := ""
	for {
		line, _, err := k.u.Ask(ctx, tui.Static(RecoverPage(k.c, errLine)))
		if err != nil {
			return err
		}
		switch strings.TrimSpace(line) {
		case "":
			return nil
		case "1":
			if errLine, err = k.resetAllowList(ctx); err != nil || errLine == "" {
				return err
			}
		case "2":
			if errLine, err = k.recoverCode(ctx); err != nil || errLine == "" {
				return err
			}
		default:
			errLine = "Type 1 or 2, or press Enter to go back."
		}
	}
}

func (k *console) resetAllowList(ctx context.Context) (string, error) {
	out, err := k.d.AccessNet.ResetAllowList(ctx, connect.NewRequest(&accessv1.ResetAllowListRequest{}))
	if err != nil {
		k.d.Logger.Warn("console: Recover access: the allow-list reset was refused", log.F("error", err.Error()))
		return "Who can connect wasn't reset: " + consoleui.Describe(err), nil
	}
	k.d.Logger.Info("console: Recover access: who can connect was reset", log.F("revert_after", out.Msg.GetRevertAfterSeconds()))
	until := time.Now().Add(time.Duration(out.Msg.GetRevertAfterSeconds()) * time.Second)
	errLine := ""
	for {
		line, _, err := k.u.Ask(ctx, func() (tui.Page, bool) { return AllowListPage(k.c, time.Until(until), errLine), false })
		if err != nil {
			return "", err
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "":
			return "", nil
		case "k":
			if _, err := k.d.AccessNet.ConfirmNetwork(ctx, connect.NewRequest(&accessv1.ConfirmNetworkRequest{Token: out.Msg.GetToken()})); err != nil {
				errLine = "The change wasn't kept: " + consoleui.Describe(err)
				continue
			}
			k.d.Logger.Info("console: Recover access: the allow-list reset was kept")
			return "", nil
		}
	}
}

func (k *console) recoverCode(ctx context.Context) (string, error) {
	r, err := k.d.Console.BeginRecoverAccess(ctx)
	if err != nil {
		k.d.Logger.Warn("console: Recover access: no code", log.F("error", err.Error()))
		return "No code was made: " + consoleui.Describe(err), nil
	}
	k.d.Logger.Info("console: Recover access: a code is out", log.F("expires", r.Expires))
	fp := k.data.Status.Status.GetTlsFingerprint()
	for {
		line, _, err := k.u.Ask(ctx, func() (tui.Page, bool) {
			if info, err := k.d.Console.Read(ctx); err == nil && info.Recover != nil {
				r = *info.Recover
				if info.CertFingerprint != "" {
					fp = info.CertFingerprint
				}
			}
			return RecoverCodePage(k.c, r, fp, k.d.Now()), false
		})
		if err != nil {
			return "", err
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "":
			return "", nil
		case "c":
			if err := k.d.Console.CancelRecoverAccess(ctx); err != nil {
				return "The code wasn't withdrawn: " + consoleui.Describe(err), nil
			}
			k.d.Logger.Info("console: Recover access: the code was withdrawn")
			return "", nil
		}
	}
}

// cancelReset stops a factory reset counting down, as the console.
func (k *console) cancelReset(ctx context.Context) {
	if k.data.Status.Status.GetFactoryReset().GetState() != osadminv1.FactoryResetState_FACTORY_RESET_STATE_COUNTDOWN {
		return
	}
	if _, err := k.d.Local.LocalCancelFactoryReset(ctx, connect.NewRequest(&osadminv1.LocalCancelFactoryResetRequest{Actor: "console"})); err != nil {
		k.d.Logger.Warn("console: the factory reset wasn't cancelled", log.F("error", err.Error()))
		return
	}
	k.d.Logger.Info("console: the factory reset was cancelled on the console")
}
