// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

// Package console_test is the image suite's run of the console: the boot
// banner and the Secure Boot choice on every console the box has, and the
// typed answer taken from whichever one it's typed on. A VMware VM with no
// serial port has only its screen; a headless box has only its serial
// line.
package console_test

import (
	"os"
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
	// wizard is the first-boot wizard, which owns the consoles once the
	// services run.
	wizard = `Setup 1 of 5: network`
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
// that wasn't there. Once the services run, the setup wizard owns the
// screen: it shows the reduced protection, lists the NIC, takes keys typed
// on the screen's keyboard, and says plainly that the network can't be
// applied while netd isn't in the build.
func TestTheScreenAloneShowsTheChoiceAndTakesTheAnswer(t *testing.T) {
	vm := boot(t, harness.Options{NoSerial: true})
	vm.ExpectScreen(banner, 5*time.Minute)
	vm.ExpectScreen(prompt, time.Minute)
	vm.Press(screens.TypedNoSecureBoot + "\r")
	vm.ExpectScreen(chosen, time.Minute)
	vm.ExpectScreen(keyfile, time.Minute)
	vm.Press("\r")
	vm.ExpectScreen(wizard, 3*time.Minute)
	vm.ExpectScreen(`!! Protection: reduced \(Secure Boot off\)`, time.Minute)
	vm.ExpectScreen(`1 eth0 `, time.Minute)
	vm.Press("1\r")
	vm.ExpectScreen(`Management interface eth0`, time.Minute)
	vm.Press("\r")
	vm.ExpectScreen(`The network service isn't installed in this build yet`, time.Minute)
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
