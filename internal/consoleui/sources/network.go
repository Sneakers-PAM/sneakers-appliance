// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1/netdv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

// NIC is one network interface.
type NIC struct {
	Name, MAC, Driver string
	// Up: the interface is brought up; only then is Link known.
	Up   bool
	Link bool
}

// The check states.
const (
	CheckRunning = "running"
	CheckOK      = "ok"
	CheckWarn    = "warn"
	CheckFailed  = "failed"
)

// Check is one network check's result.
type Check struct {
	Name, State, Code, Detail string
	Skippable                 bool
}

// Addresses is what the box has on the network now.
type Addresses struct {
	Management, Service []string
	Hostname            string
	NTPSynced           bool
}

// Network is netd as the console uses it.
type Network interface {
	// Installed reports whether netd is in this build.
	Installed() bool
	Interfaces(ctx context.Context) ([]NIC, error)
	Get(ctx context.Context) (network.Settings, error)
	// Set applies s live; it reverts after revertAfter seconds unless
	// confirmed with token.
	Set(ctx context.Context, s network.Settings) (token string, revertAfter int, err error)
	Confirm(ctx context.Context, token string) error
	Checks(ctx context.Context) ([]Check, error)
	Status(ctx context.Context) (Addresses, error)
}

// SysClassNet is where the kernel lists the network interfaces.
const SysClassNet = "/sys/class/net"

var errNoNetd = NotInstalled{What: whatOf("netd")}

// NewNetwork is netd through c when the service table in dir has it, and
// the stub otherwise. Both read the interface list from sysfs.
func NewNetwork(dir string, c netdv1connect.NetworkServiceClient, sys string) Network {
	if Installed(dir, "netd") {
		return netd{c: c, sys: sys}
	}
	return netStub{sys: sys}
}

// netStub is the network before netd is in the build: the interface list
// is real (sysfs), and nothing can be set or checked.
type netStub struct{ sys string }

func (n netStub) Installed() bool                                          { return false }
func (n netStub) Interfaces(context.Context) ([]NIC, error)                { return readNICs(n.sys) }
func (netStub) Get(context.Context) (network.Settings, error)              { return network.Settings{}, errNoNetd }
func (netStub) Confirm(context.Context, string) error                      { return errNoNetd }
func (netStub) Checks(context.Context) ([]Check, error)                    { return nil, errNoNetd }
func (netStub) Status(context.Context) (Addresses, error)                  { return Addresses{}, errNoNetd }
func (netStub) Set(context.Context, network.Settings) (string, int, error) { return "", 0, errNoNetd }

// netd is the real network service.
type netd struct {
	c   netdv1connect.NetworkServiceClient
	sys string
}

func (n netd) Installed() bool                           { return true }
func (n netd) Interfaces(context.Context) ([]NIC, error) { return readNICs(n.sys) }

func (n netd) Get(ctx context.Context) (network.Settings, error) {
	r, err := n.c.Get(ctx, connect.NewRequest(&netdv1.GetRequest{}))
	if err != nil {
		return network.Settings{}, err
	}
	return network.FromWire(r.Msg.GetSettings())
}

func (n netd) Set(ctx context.Context, s network.Settings) (string, int, error) {
	r, err := n.c.Set(ctx, connect.NewRequest(&netdv1.SetRequest{Settings: network.ToWire(s)}))
	if err != nil {
		return "", 0, err
	}
	return r.Msg.GetToken(), int(r.Msg.GetRevertAfterSeconds()), nil
}

func (n netd) Confirm(ctx context.Context, token string) error {
	_, err := n.c.Confirm(ctx, connect.NewRequest(&netdv1.ConfirmRequest{Token: token}))
	return err
}

var checkStates = map[netdv1.CheckState]string{
	netdv1.CheckState_CHECK_STATE_OK:     CheckOK,
	netdv1.CheckState_CHECK_STATE_WARN:   CheckWarn,
	netdv1.CheckState_CHECK_STATE_FAILED: CheckFailed,
}

func (n netd) Checks(ctx context.Context) ([]Check, error) {
	r, err := n.c.Checks(ctx, connect.NewRequest(&netdv1.ChecksRequest{}))
	if err != nil {
		return nil, err
	}
	var out []Check
	for _, c := range r.Msg.GetChecks() {
		st, ok := checkStates[c.GetState()]
		if !ok {
			st = CheckRunning
		}
		out = append(out, Check{Name: c.GetName(), State: st, Code: c.GetCode(), Detail: c.GetDetail(), Skippable: c.GetSkippable()})
	}
	return out, nil
}

func (n netd) Status(ctx context.Context) (Addresses, error) {
	r, err := n.c.Status(ctx, connect.NewRequest(&netdv1.StatusRequest{}))
	if err != nil {
		return Addresses{}, err
	}
	m := r.Msg
	return Addresses{Management: m.GetManagementAddresses(), Service: m.GetServiceAddresses(), Hostname: m.GetHostname(), NTPSynced: m.GetNtpSynced()}, nil
}

// iffUp is IFF_UP in an interface's flags.
const iffUp = 0x1

// readNICs lists the interfaces with a device behind them (the loopback
// and virtual ones have none), sorted by name.
func readNICs(sys string) ([]NIC, error) {
	entries, err := os.ReadDir(sys)
	if err != nil {
		return nil, err
	}
	read := func(p string) string {
		b, _ := os.ReadFile(p) // #nosec G304 -- sysfs attributes
		return strings.TrimSpace(string(b))
	}
	var out []NIC
	for _, e := range entries {
		d := filepath.Join(sys, e.Name())
		if _, err := os.Stat(filepath.Join(d, "device")); err != nil {
			continue
		}
		flags, _ := strconv.ParseUint(strings.TrimPrefix(read(filepath.Join(d, "flags")), "0x"), 16, 32)
		n := NIC{Name: e.Name(), MAC: read(filepath.Join(d, "address")), Up: flags&iffUp != 0}
		n.Link = n.Up && read(filepath.Join(d, "operstate")) == "up"
		if drv, err := os.Readlink(filepath.Join(d, "device", "driver")); err == nil {
			n.Driver = filepath.Base(drv)
		}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
