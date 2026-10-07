// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"

	"connectrpc.com/connect"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
)

// Services starts init's on-demand services (sshd and osadmin during
// setup) and reads whether they run.
type Services interface {
	Start(ctx context.Context, name string) error
	Running(ctx context.Context, name string) (bool, error)
}

// NewServices is init's ServicesService through c, for the services the
// table in dir has; any other answers NotInstalled without asking init.
func NewServices(dir string, c initv1connect.ServicesServiceClient) Services {
	return services{dir: dir, c: c}
}

type services struct {
	dir string
	c   initv1connect.ServicesServiceClient
}

func (s services) Start(ctx context.Context, name string) error {
	if !Installed(s.dir, name) {
		return NotInstalled{What: whatOf(name)}
	}
	_, err := s.c.Start(ctx, connect.NewRequest(&initv1.StartRequest{Name: name}))
	return err
}

func (s services) Running(ctx context.Context, name string) (bool, error) {
	if !Installed(s.dir, name) {
		return false, NotInstalled{What: whatOf(name)}
	}
	r, err := s.c.Status(ctx, connect.NewRequest(&initv1.StatusRequest{Name: name}))
	if err != nil {
		return false, err
	}
	return r.Msg.GetRunning(), nil
}

// Upgrade is the upgrade service's state, for the maintenance view.
type Upgrade struct {
	InProgress bool
	Version    string
	Step       string
	// Failed is the error of an upgrade that was rolled back.
	Failed string
}

// Upgrades is the upgrade service (spec 5).
type Upgrades interface {
	Current(ctx context.Context) (Upgrade, error)
}

// NoUpgrades is the upgrade service's stub until it's in the build: the
// console falls back to the staged and failed versions on Status.
type NoUpgrades struct{}

// Current answers NotInstalled.
func (NoUpgrades) Current(context.Context) (Upgrade, error) {
	return Upgrade{}, NotInstalled{What: "The upgrade service"}
}

// PlatformState is the platform as the status view shows it: its state,
// and how many nodes run it (this box alone until the join path exists).
type PlatformState struct {
	State string
	Nodes int
}

// Platform is the platform's state (spec 3: k0s and platformd).
type Platform interface {
	State(ctx context.Context) (PlatformState, error)
}

// NoPlatform is the platform's stub until it's in the build.
type NoPlatform struct{}

// State answers NotInstalled.
func (NoPlatform) State(context.Context) (PlatformState, error) {
	return PlatformState{}, NotInstalled{What: whatOf("platform")}
}
