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
	booted = `services: entering phase phase=firstboot`
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
// that wasn't there.
func TestTheScreenAloneShowsTheChoiceAndTakesTheAnswer(t *testing.T) {
	vm := boot(t, harness.Options{NoSerial: true})
	vm.ExpectScreen(banner, 5*time.Minute)
	vm.ExpectScreen(prompt, time.Minute)
	vm.Press(screens.TypedNoSecureBoot + "\r")
	vm.ExpectScreen(chosen, time.Minute)
	vm.ExpectScreen(booted, time.Minute)
}

// No display: the serial line alone carries the banner, the choice and the
// answer.
func TestTheSerialLineAloneShowsTheChoiceAndTakesTheAnswer(t *testing.T) {
	vm := boot(t, harness.Options{NoVGA: true})
	vm.Expect(banner, 5*time.Minute)
	vm.Expect(prompt, time.Minute)
	vm.Type(screens.TypedNoSecureBoot + "\r")
	vm.Expect(chosen, time.Minute)
	vm.Expect(booted, time.Minute)
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
	vm.Expect(booted, time.Minute)
}
