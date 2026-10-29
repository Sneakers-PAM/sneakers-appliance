// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package services_test

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/phase"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/services"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/vports"
)

// The guest agent answers spec 1 Section 2.8's RPCs and nothing else, on
// the port init links by name, from first boot on.
func TestTheGuestAgentAnswersOnlyItsRPCs(t *testing.T) {
	tbl, err := services.Load(os.DirFS("../../os/rootfs"), "services.d")
	if err != nil {
		t.Fatal(err)
	}
	g, ok := tbl["qemu-ga"]
	if !ok {
		t.Fatal("no qemu-ga")
	}
	port := vports.DevDir + "/virtio-ports/org.qemu.guest_agent.0"
	if g.Exec != "/usr/bin/qemu-ga" || g.User != "" || g.Restart != services.RestartAlways ||
		!g.In(phase.Firstboot) || !g.In(phase.Normal) || !slices.Equal(g.StartWhen, []string{port}) {
		t.Fatalf("qemu-ga: %+v", g)
	}
	var allowed []string
	for _, a := range g.Args {
		if v, ok := strings.CutPrefix(a, "--allow-rpcs="); ok {
			allowed = strings.Split(v, ",")
		}
	}
	want := []string{
		"guest-fsfreeze-freeze", "guest-fsfreeze-freeze-list", "guest-fsfreeze-status", "guest-fsfreeze-thaw",
		"guest-get-host-name", "guest-get-osinfo", "guest-info", "guest-network-get-interfaces",
		"guest-ping", "guest-shutdown", "guest-sync", "guest-sync-delimited",
	}
	slices.Sort(allowed)
	if !slices.Equal(allowed, want) {
		t.Fatalf("allowed %v, want %v", allowed, want)
	}
	if !slices.Contains(g.Args, "--path="+port) || !slices.Contains(g.Args, "--method=virtio-serial") {
		t.Fatalf("args %v", g.Args)
	}
	for _, a := range g.Args {
		if strings.HasPrefix(a, "--block-rpcs") || strings.HasPrefix(a, "--fsfreeze-hook") || strings.HasPrefix(a, "--config") {
			t.Fatalf("an argument that widens or bypasses the allow-list: %s", a)
		}
	}
}
