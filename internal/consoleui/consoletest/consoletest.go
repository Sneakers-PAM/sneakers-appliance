// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package consoletest is a box for the console's tests: fakes of init's
// services, netd and the access backend's console API.
package consoletest

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

// Services is init's on-demand services: it records each start.
type Services struct {
	mu      sync.Mutex
	Started []string
	// Missing are services the table doesn't have.
	Missing map[string]bool
}

// Start starts name; like init, starting a running service does nothing.
func (s *Services) Start(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Missing[name] {
		return sources.NotInstalled{What: "The " + map[string]string{"sshd": "SSH service", "netd": "network service"}[name]}
	}
	if !slices.Contains(s.Started, name) {
		s.Started = append(s.Started, name)
	}
	return nil
}

// Running reports whether name was started.
func (s *Services) Running(_ context.Context, name string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Missing[name] {
		return false, sources.NotInstalled{What: "The service"}
	}
	for _, n := range s.Started {
		if n == name {
			return true, nil
		}
	}
	return false, nil
}

// Starts is what was started so far.
func (s *Services) Starts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.Started...)
}

// Network is netd for the console: two NICs, and checks that report what
// Results says.
type Network struct {
	mu       sync.Mutex
	Applied  []network.Settings
	Kept     []string
	Results  []sources.Check
	Addrs    []string
	NoNetd   bool
	NICs     []sources.NIC
	Ports    []string
	checkRun int
}

// Installed reports whether this netd is installed.
func (n *Network) Installed() bool { return !n.NoNetd }

var errNoNetd = sources.NotInstalled{What: "The network service"}

// Interfaces lists the NICs.
func (n *Network) Interfaces(context.Context) ([]sources.NIC, error) {
	if n.NICs != nil {
		return n.NICs, nil
	}
	return []sources.NIC{{Name: "ens192", MAC: "00:50:56:00:00:01", Driver: "vmxnet3", Up: true, Link: true}, {Name: "ens224", MAC: "00:50:56:00:00:02", Driver: "vmxnet3", Up: true}}, nil
}

// Get has no settings yet.
func (n *Network) Get(context.Context) (network.Settings, error) {
	if n.NoNetd {
		return network.Settings{}, errNoNetd
	}
	return network.Settings{}, nil
}

// Set records s.
func (n *Network) Set(_ context.Context, s network.Settings) (string, int, error) {
	if n.NoNetd {
		return "", 0, errNoNetd
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Applied = append(n.Applied, s)
	n.checkRun = 0
	return "T1", 120, nil
}

// Confirm records the kept token.
func (n *Network) Confirm(_ context.Context, token string) error {
	if n.NoNetd {
		return errNoNetd
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Kept = append(n.Kept, token)
	return nil
}

// Checks reports running once, then Results.
func (n *Network) Checks(context.Context) ([]sources.Check, error) {
	if n.NoNetd {
		return nil, errNoNetd
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.checkRun++
	if n.checkRun == 1 {
		return []sources.Check{{Name: "link", State: sources.CheckRunning}}, nil
	}
	return n.Results, nil
}

// Status has the addresses.
func (n *Network) Status(context.Context) (sources.Addresses, error) {
	if n.NoNetd {
		return sources.Addresses{}, errNoNetd
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return sources.Addresses{Management: append([]string(nil), n.Addrs...), Hostname: "sneakers.example.org", NTPSynced: true}, nil
}

// SetAddrs changes the management addresses, as a DHCP lease does.
func (n *Network) SetAddrs(addrs ...string) {
	n.mu.Lock()
	n.Addrs = addrs
	n.mu.Unlock()
}

// Settle is a short wait for a background change to land.
func Settle() { time.Sleep(20 * time.Millisecond) }

// SetManagementPorts records each opening, as "ssh" or "ssh+https".
func (n *Network) SetManagementPorts(_ context.Context, ssh, https bool) error {
	if n.NoNetd {
		return errNoNetd
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	var p []string
	if ssh {
		p = append(p, "ssh")
	}
	if https {
		p = append(p, "https")
	}
	n.Ports = append(n.Ports, strings.Join(p, "+"))
	return nil
}

// Opened is every port opening so far.
func (n *Network) Opened() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.Ports...)
}

// Settings are the settings applied so far.
func (n *Network) Settings() []network.Settings {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]network.Settings(nil), n.Applied...)
}

// Tokens are the tokens kept so far.
func (n *Network) Tokens() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.Kept...)
}

// SetResults changes what the checks report.
func (n *Network) SetResults(cs []sources.Check) {
	n.mu.Lock()
	n.Results = cs
	n.mu.Unlock()
}

// Console is the access backend's console API: the info it's given, and
// what the console asked of it.
type Console struct {
	mu       sync.Mutex
	info     sources.ConsoleInfo
	changed  chan struct{}
	Resets   int
	Recovers int
	Cancels  int
	// RecoverErr is BeginRecoverAccess's answer when set.
	RecoverErr error
}

// NewConsole is a backend with a setup code waiting.
func NewConsole() *Console {
	return &Console{changed: make(chan struct{}, 1), info: sources.ConsoleInfo{
		SetupCode: "7PQK-NMS9-XD2A-4KJW", CodeExpires: time.Date(2026, 10, 7, 15, 3, 0, 0, time.UTC), AttemptsLeft: 5,
		URL: "https://192.0.2.10:8443", URLs: []string{"https://192.0.2.10:8443"}, SetupSteps: 6,
		CertFingerprint: "7C2E91AB4F06D3E8B15A6C902E7F0A4DE38B5C219FD076A4C1E90B3F8D62A7C5",
	}}
}

// Set changes the info, as the backend does, and signals it.
func (c *Console) Set(f func(*sources.ConsoleInfo)) {
	c.mu.Lock()
	f(&c.info)
	c.mu.Unlock()
	select {
	case c.changed <- struct{}{}:
	default:
	}
}

// Read returns the info.
func (c *Console) Read(context.Context) (sources.ConsoleInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.info, nil
}

// Changed is signalled on every Set.
func (c *Console) Changed() <-chan struct{} { return c.changed }

// Watch has nothing to follow: Set signals Changed itself.
func (c *Console) Watch(context.Context) {}

// ResetSetupCode records the reset and shows a new code.
func (c *Console) ResetSetupCode(context.Context) error {
	c.mu.Lock()
	c.Resets++
	c.info.State, c.info.SetupCode, c.info.SetupSource, c.info.CodeLocked = sources.SetupNotStarted, "4KJW-XD2A-7PQK-NMS9", "", false
	c.mu.Unlock()
	return nil
}

// BeginRecoverAccess issues a Recover access code.
func (c *Console) BeginRecoverAccess(context.Context) (sources.RecoverCode, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.RecoverErr != nil {
		return sources.RecoverCode{}, c.RecoverErr
	}
	c.Recovers++
	rc := sources.RecoverCode{Code: "6HDW-2RTE-KM8Q-0VXA", Expires: time.Date(2026, 10, 7, 15, 3, 0, 0, time.UTC), AttemptsLeft: 5, URL: "https://192.0.2.10:8443/recover"}
	c.info.Recover = &rc
	return rc, nil
}

// CancelRecoverAccess withdraws the code.
func (c *Console) CancelRecoverAccess(context.Context) error {
	c.mu.Lock()
	c.Cancels++
	c.info.Recover = nil
	c.mu.Unlock()
	return nil
}

// Counts are the resets, Recover access codes and cancels so far.
func (c *Console) Counts() (resets, recovers, cancels int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Resets, c.Recovers, c.Cancels
}
