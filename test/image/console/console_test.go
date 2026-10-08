// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

// Package console_test is the image suite's run of the console: the boot
// banner and the Secure Boot choice on every console the box has, the
// typed answer taken from whichever one it's typed on, and the first-boot
// info screen on the screen alone. A VMware VM with no serial port has
// only its screen; a headless box has only its serial line.
package console_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/screens"
	"github.com/Sneakers-PAM/sneakers-appliance/test/image/harness"
)

const (
	banner = `sneakers-init: phase=enrol protection=pending`
	prompt = `type "` + screens.TypedNoSecureBoot + `" and press Enter`
	chosen = `Secure Boot choice off recorded on the ESP`
	// keyfile is the end of first boot's protection step on a box without
	// a TPM; Enter goes on with the key file.
	keyfile = `Press Enter to continue`
	booted  = `services: entering phase phase=firstboot`
	// info is the first-boot info screen, which owns the consoles once the
	// services run; QEMU's user network leases the first guest its first
	// address.
	info = `Open this address in your browser:`
	url  = `https://10\.0\.2\.15:8443` // scrub:allow=private-ip -- QEMU's user network
	code = `Setup code [0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}`
)

func boot(t *testing.T, o harness.Options) *harness.VM {
	t.Helper()
	img, keys := os.Getenv("SNEAKERS_IMAGE"), os.Getenv("SNEAKERS_KEYS")
	harness.Need(t, nil, img, keys)
	// Keys enrolled with Secure Boot off and no TPM: VMware's shape.
	o.SecureBoot, o.Keys, o.Disks = harness.OffWithKeys, keys, []harness.Disk{{Image: img}}
	return harness.Boot(t, o)
}

// No serial port, Secure Boot off, no TPM: the VMware VM the lab first ran
// on, whose screen stayed black because init's console was a serial port
// that wasn't there. Once the services run, first boot owns the screen and
// asks nothing: it shows the :8443 address on the DHCP lease, the one-time
// setup code and the reduced protection, in the large font.
func TestTheScreenAloneShowsTheChoiceThenTheSetupInfo(t *testing.T) {
	vm := boot(t, harness.Options{NoSerial: true})
	vm.ExpectScreen(banner, 5*time.Minute)
	vm.ExpectScreen(prompt, time.Minute)
	vm.Press(screens.TypedNoSecureBoot + "\r")
	vm.ExpectScreen(chosen, time.Minute)
	vm.ExpectScreen(keyfile, time.Minute)
	vm.Press("\r")
	vm.ExpectScreen(info, 3*time.Minute)
	vm.ExpectScreen(url, 2*time.Minute)
	vm.ExpectScreen(code, time.Minute)
	vm.ExpectScreen(`Protection REDUCED`, time.Minute)
	t.Logf("the info screen:\n%s", strings.Join(vm.Screen(), "\n"))
}

// No display: the serial line alone carries the banner, the choice and the
// answer.
func TestTheSerialLineAloneShowsTheChoiceAndTakesTheAnswer(t *testing.T) {
	vm := boot(t, harness.Options{NoVGA: true})
	vm.Expect(banner, 5*time.Minute)
	vm.Expect(prompt, time.Minute)
	vm.Type(screens.TypedNoSecureBoot + "\r")
	vm.Expect(chosen, time.Minute)
	vm.Expect(keyfile, time.Minute)
	vm.Type("\r")
	vm.Expect(booted, 3*time.Minute)
}

// Both: each shows the choice, and an answer typed on the screen's
// keyboard is taken while the serial line watches.
func TestBothConsolesShowTheChoiceAndTheScreenCanAnswer(t *testing.T) {
	vm := boot(t, harness.Options{})
	vm.Expect(prompt, 5*time.Minute)
	vm.ExpectScreen(prompt, time.Minute)
	vm.Press(screens.TypedNoSecureBoot + "\r")
	vm.Expect(chosen, time.Minute)
	vm.ExpectScreen(chosen, time.Minute)
	vm.ExpectScreen(keyfile, time.Minute)
	vm.Press("\r")
	vm.Expect(booted, 3*time.Minute)
}
