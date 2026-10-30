// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1/netdv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/initapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netdapi"
)

// The box's paths the console reads.
const (
	// SSHDir holds the SSH host keys (osadmin's Paths.SSHDir on the box).
	SSHDir = "/var/lib/sneakers/ssh"
)

// netdTimeout is the most any netd call from the console takes, above the
// deadline the network editor sets on its longest call.
const netdTimeout = 30 * time.Second

// NetdClient is the console's netd client on sock. Unlike netdapi.NewClient
// it has a timeout: the console makes no streaming calls, and a netd that
// stops answering must fail the call, never hang the console.
func NetdClient(sock string, timeout time.Duration) netdv1connect.NetworkServiceClient {
	hc := UnixClient(sock)
	hc.Timeout = timeout
	return netdv1connect.NewNetworkServiceClient(hc, "http://netd.sock")
}

// Box is every client the console programs use, on the box's sockets.
type Box struct {
	Custody   Custody
	Status    Status
	Network   Network
	Services  Services
	Access    accessv1connect.AccessServiceClient
	Setup     accessv1connect.SetupServiceClient
	AccessNet accessv1connect.NetworkServiceClient
	// Console is the access backend's console API.
	Console  ConsoleAccess
	Local    osadminv1connect.LocalServiceClient
	Power    initv1connect.PowerServiceClient
	SSHDir   string
	Platform Platform
}

// Dial makes the console's clients. Nothing connects until a call.
func Dial() Box {
	ic, ac, pc := UnixClient(initapi.SocketPath), UnixClient(accessapi.SocketPath), UnixClient(initapi.PowerSocketPath)
	const initURL, accessURL, powerURL = "http://init.sock", "http://access.sock", "http://power.sock"
	b := Box{
		Custody:   Custody{C: initv1connect.NewKeyCustodyServiceClient(ic, initURL)},
		Status:    Status{Access: accessv1connect.NewAccessServiceClient(ac, accessURL), CacheFile: accessapi.StatusFile},
		Network:   NewNetwork(ServicesDir, NetdClient(netdapi.SocketPath, netdTimeout), SysClassNet),
		Services:  NewServices(ServicesDir, initv1connect.NewServicesServiceClient(ic, initURL)),
		Access:    accessv1connect.NewAccessServiceClient(ac, accessURL),
		Setup:     accessv1connect.NewSetupServiceClient(ac, accessURL),
		AccessNet: accessv1connect.NewNetworkServiceClient(ac, accessURL),
		Local:     osadminv1connect.NewLocalServiceClient(ac, accessURL),
		Power:     initv1connect.NewPowerServiceClient(pc, powerURL),
		SSHDir:    SSHDir,
		Platform:  NoPlatform{},
	}
	b.Console = &AccessConsole{Setup: b.Setup}
	return b
}
