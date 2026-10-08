// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/initapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netdapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

// The box's paths the console reads.
const (
	// SSHDir holds the SSH host keys (osadmin's Paths.SSHDir on the box).
	SSHDir = "/var/lib/sneakers/ssh"
)

// Box is every client the console programs use, on the box's sockets.
type Box struct {
	Custody  Custody
	Status   Status
	Network  Network
	Services Services
	Access   accessv1connect.AccessServiceClient
	Setup    accessv1connect.SetupServiceClient
	Local    osadminv1connect.LocalServiceClient
	Power    initv1connect.PowerServiceClient
	Shell    *shell.Services
	SSHDir   string
	Platform Platform
	Upgrades Upgrades
}

// Dial makes the console's clients. Nothing connects until a call.
func Dial() Box {
	ic, ac, pc := UnixClient(initapi.SocketPath), UnixClient(accessapi.SocketPath), UnixClient(initapi.PowerSocketPath)
	const initURL, accessURL, powerURL = "http://init.sock", "http://access.sock", "http://power.sock"
	b := Box{
		Custody:  Custody{C: initv1connect.NewKeyCustodyServiceClient(ic, initURL)},
		Status:   Status{Access: accessv1connect.NewAccessServiceClient(ac, accessURL), CacheFile: accessapi.StatusFile},
		Network:  NewNetwork(ServicesDir, netdapi.NewClient(netdapi.SocketPath), SysClassNet),
		Services: NewServices(ServicesDir, initv1connect.NewServicesServiceClient(ic, initURL)),
		Access:   accessv1connect.NewAccessServiceClient(ac, accessURL),
		Setup:    accessv1connect.NewSetupServiceClient(ac, accessURL),
		Local:    osadminv1connect.NewLocalServiceClient(ac, accessURL),
		Power:    initv1connect.NewPowerServiceClient(pc, powerURL),
		SSHDir:   SSHDir,
		Platform: NoPlatform{},
		Upgrades: NoUpgrades{},
	}
	b.Shell = &shell.Services{Power: b.Power, StatusFile: accessapi.StatusFile}
	b.Shell.UseAccessd(ac, accessURL)
	return b
}
