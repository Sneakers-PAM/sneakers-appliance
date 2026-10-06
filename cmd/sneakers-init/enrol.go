// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"io"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/screens"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/secureboot"
)

// enrolDeps are what the enrol phase touches, so its flow tests without a
// firmware or a console.
type enrolDeps struct {
	vars      secureboot.Vars
	material  func() (secureboot.Material, error)
	choice    string // from the ESP: "on", "off" or ""
	setChoice func(string) error
	platform  screens.Platform
	in        io.Reader
	out       io.Writer
	logf      func(string, ...any)
}

// enrolOutcome is what init does next.
type enrolOutcome int

const (
	// enrolReboot: keys were written; reboot (QEMU, Proxmox) or wait for
	// the admin's power cycle (VMware, bare metal).
	enrolReboot enrolOutcome = iota
	// enrolReduced: the admin chose to run without Secure Boot.
	enrolReduced
)

// runEnrol is the enrol phase: the choice screen when nothing is chosen,
// then enrolment from Setup Mode, or the clear-the-keys steps when the
// firmware isn't in Setup Mode (writing nothing), until the keys are in or
// the admin types "no secure boot".
func runEnrol(d enrolDeps) (enrolOutcome, error) {
	lines := bufio.NewScanner(d.in)
	ask := func(screen string) (string, bool) {
		for {
			_, _ = fmt.Fprint(d.out, screen)
			if !lines.Scan() {
				return "", false
			}
			if c, ok := screens.Choice(lines.Text()); ok {
				return c, true
			}
		}
	}
	choice := d.choice
	if choice == "" {
		c, ok := ask(screens.SecureBootChoice(d.platform))
		if !ok {
			return 0, fmt.Errorf("init: the console closed at the Secure Boot choice")
		}
		choice = c
		if err := d.setChoice(c); err != nil {
			return 0, err
		}
		d.logf("init: Secure Boot choice %s recorded on the ESP", c)
	}
	for choice == secureboot.ChoiceOn {
		m, err := d.material()
		if err != nil {
			return 0, err
		}
		err = secureboot.Enrol(d.vars, m, d.logf)
		switch {
		case err == nil:
			_, _ = fmt.Fprint(d.out, screens.Enrolled(d.platform))
			return enrolReboot, nil
		case codes.Is(err, codes.SBNotSetupMode):
			d.logf("init: firmware not in Setup Mode; nothing written")
			c, ok := ask(screens.ClearKeys(d.platform))
			if !ok {
				return 0, fmt.Errorf("init: the console closed at the clear-the-keys screen")
			}
			if c == secureboot.ChoiceOff {
				if err := d.setChoice(c); err != nil {
					return 0, err
				}
				choice = c
			}
			// Enter: the admin cleared the keys; try again.
		default:
			return 0, err
		}
	}
	return enrolReduced, nil
}
