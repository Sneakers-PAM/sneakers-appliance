// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

// Package proxmox_test is the image suite's item 10 (spec 1 Section 6): the
// qcow2 the kit writes, booted the way proxmox-vm.md sets the VM up (q35,
// OVMF with an EFI vars store without pre-enrolled keys, a TPM v2.0, the
// disk on its own VirtIO SCSI controller, a VirtIO NIC and the guest agent
// port). The box enrols the org keys from Setup Mode, restarts, comes up
// with Secure Boot enforcing and TPM custody, and its guest agent answers
// only the RPCs spec 1 Section 2.8 allows; the hypervisor's shutdown
// drains the box and powers it off.
package proxmox_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/screens"
	"github.com/Sneakers-PAM/sneakers-appliance/test/image/harness"
)

func TestProxmoxShape(t *testing.T) {
	img := os.Getenv("SNEAKERS_QCOW2")
	harness.Need(t, nil, img)
	opts := harness.Options{SecureBoot: harness.SetupMode, TPM: true, SCSI: true, GuestAgent: true}

	opts.Disks = []harness.Disk{{Image: img, Format: "qcow2"}}
	first := harness.Boot(t, opts)
	first.Expect(`sneakers-init: phase=enrol`, 5*time.Minute)
	first.Expect(`Press Enter to keep 1`, time.Minute)
	first.Type("\r")
	first.Expect(regexp.QuoteMeta(strings.TrimSpace(screens.Enrolled(screens.QEMU))), 2*time.Minute)
	first.WaitExit(2 * time.Minute)

	opts.Disks = []harness.Disk{{Image: first.Disk(0), Format: "qcow2", Move: true}}
	opts.Vars, opts.TPMState = first.Vars(), first.TPMState()
	vm := harness.Boot(t, opts)
	vm.Expect(`sneakers-init: phase=firstboot protection=full`, 5*time.Minute)
	vm.Expect(`Use the TPM \(recommended\)`, time.Minute)
	vm.Type("\r")
	vm.Expect(`custody fixed \(TPM\); state and backup formatted and mounted`, 3*time.Minute)
	vm.Expect(`Protection: full`, time.Minute)
	vm.Expect(`services: entering phase phase=firstboot`, time.Minute)

	if r := vm.Agent("guest-ping", 3*time.Minute); r.Error != nil {
		t.Fatalf("guest-ping: %s: %s", r.Error.Class, r.Error.Desc)
	}
	if r := vm.Agent("guest-network-get-interfaces", time.Minute); r.Error != nil || !strings.Contains(string(r.Return), `"name"`) {
		t.Fatalf("guest-network-get-interfaces: %+v %s", r.Error, r.Return)
	}
	for _, refused := range []string{"guest-exec", "guest-exec-status", "guest-file-open", "guest-set-user-password", "guest-ssh-add-authorized-keys"} {
		r := vm.Agent(refused, time.Minute)
		if r.Error == nil || !strings.Contains(r.Error.Desc, "disabled") {
			t.Errorf("%s isn't refused: %+v %s", refused, r.Error, r.Return)
		}
	}

	// While first boot owns the consoles, init's "power: accepted" line goes
	// to the console log; the drain and the power-off reach the serial line
	// once the console program has stopped.
	vm.AgentNoReply("guest-shutdown", time.Minute)
	vm.Expect(`services: drained .*service=accessd`, 15*time.Minute)
	vm.Expect(`power: powering off`, 5*time.Minute)
	vm.WaitExit(2 * time.Minute)
}
