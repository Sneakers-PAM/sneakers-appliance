// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Command sneakers-hvpower is /sbin/poweroff, /sbin/halt and /sbin/reboot
// on the box: the QEMU guest agent runs one of them when the hypervisor
// asks for a shutdown (Proxmox VE's Shutdown and Reboot), and it asks init
// for the same drained power-off or reboot the closed shell gets. init
// takes it from this program only when it runs as root (spec 1 Section
// 2.8).
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"connectrpc.com/connect" // scrub:allow=fqdn -- the Connect RPC module's import path

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/initapi"
)

type action int

const (
	powerOff action = iota + 1
	reboot
)

// actionFor is what the program was run as.
func actionFor(argv0 string) (action, error) {
	switch filepath.Base(argv0) {
	case "poweroff", "halt":
		return powerOff, nil
	case "reboot":
		return reboot, nil
	}
	return 0, fmt.Errorf("run as poweroff, halt or reboot, not %s", filepath.Base(argv0))
}

func main() {
	a, err := actionFor(os.Args[0])
	if err != nil {
		fail(err)
	}
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", initapi.PowerSocketPath)
		},
	}, Timeout: 30 * time.Second}
	c := initv1connect.NewPowerServiceClient(hc, "http://power.sock")
	ctx := context.Background()
	if a == reboot {
		_, err = c.Reboot(ctx, connect.NewRequest(&initv1.RebootRequest{}))
	} else {
		_, err = c.PowerOff(ctx, connect.NewRequest(&initv1.PowerOffRequest{}))
	}
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	_, _ = fmt.Fprintln(os.Stderr, "sneakers-hvpower:", err)
	os.Exit(1)
}
