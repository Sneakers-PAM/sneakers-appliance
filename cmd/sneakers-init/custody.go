// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/screens"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/phase"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/secureboot"
)

// custodian is keycustody.Custody as init's boot uses it.
type custodian interface {
	Load(ctx context.Context) (keycustody.Header, error)
	Initialize(ctx context.Context, mode keycustody.Mode, sb keycustody.SB) error
	Unlock(ctx context.Context) error
	OnBoot(ctx context.Context, sb secureboot.State) error
	Header() keycustody.Header
}

// stateDeps are what opening the state touches, so the flow tests without
// a disk or a console.
type stateDeps struct {
	custody custodian
	hasTPM  bool
	sb      secureboot.State
	// choice is the Secure Boot choice so far: the ESP's before first
	// boot fixes it.
	choice phase.SB
	in     io.Reader
	out    io.Writer
	logf   func(string, ...any)
}

// readHeader reads the custody header; initialized is false on a box whose
// first boot hasn't fixed the custody yet.
func readHeader(ctx context.Context, c custodian) (keycustody.Header, bool, error) {
	h, err := c.Load(ctx)
	if codes.Is(err, codes.KeyCustodyNotInitialized) {
		return keycustody.Header{}, false, nil
	}
	if err != nil {
		return keycustody.Header{}, false, err
	}
	return h, true, nil
}

var modeWords = map[keycustody.Mode]string{keycustody.ModeTPM: "TPM", keycustody.ModeKeyfile: "key file"}

// openState unlocks and mounts the state and backup volumes of a box set up
// before, or, on first boot, runs the protection step and initializes the
// custody, which formats and mounts them. When it returns an error the
// console has the reason and nothing may start.
func openState(ctx context.Context, d stateDeps, initialized bool) error {
	if initialized {
		if err := d.custody.Unlock(ctx); err != nil {
			_, _ = fmt.Fprint(d.out, screens.StateLocked(codes.Describe(err)))
			return err
		}
		h := d.custody.Header()
		_, _ = fmt.Fprintf(d.out, "sneakers-init: state and backup unlocked and mounted (%s, from the LUKS2 header)\n", modeWords[h.Mode])
		d.logf("init: state unlocked: custody %s, Secure Boot %s", h.Mode, h.SecureBoot)
		// A failed reseal leaves the copies that unlocked this boot in
		// place, so the box keeps running and tries again next boot.
		if err := d.custody.OnBoot(ctx, d.sb); err != nil {
			d.logf("init: the Secure Boot transition didn't finish: %s", codes.Describe(err))
		}
	} else {
		mode, err := protectionStep(d)
		if err != nil {
			return err
		}
		sb := keycustody.SBOff
		if d.choice != phase.SBOff && d.sb.Supported && d.sb.Enforcing && d.sb.OrgOnly {
			sb = keycustody.SBOn
		}
		d.logf("init: initializing custody %s with Secure Boot %s", mode, sb)
		if err := d.custody.Initialize(ctx, mode, sb); err != nil {
			_, _ = fmt.Fprintln(d.out, "sneakers-init: first boot can't set up the state volumes:", codes.Describe(err))
			return err
		}
		_, _ = fmt.Fprintf(d.out, "sneakers-init: custody fixed (%s); state and backup formatted and mounted\n", modeWords[mode])
	}
	h := d.custody.Header()
	_, _ = fmt.Fprintln(d.out, "sneakers-init: "+screens.ProtectionText(keycustody.ProtectionFor(d.sb, h.SecureBoot, h.Mode), h.Mode))
	return nil
}

// protectionStep is first boot's at-rest protection screen: the Secure Boot
// facts, then the TPM (Enter) or the typed "key file" on a box with a TPM,
// or Enter to go on with the key file on a box without one.
func protectionStep(d stateDeps) (keycustody.Mode, error) {
	choice := keycustody.SBOff
	if d.choice != phase.SBOff {
		choice = keycustody.SBOn
	}
	sbLine := screens.ProtectionText(keycustody.ProtectionFor(d.sb, choice, keycustody.ModeTPM), keycustody.ModeTPM)
	lines := bufio.NewScanner(d.in)
	if !d.hasTPM {
		_, _ = fmt.Fprint(d.out, screens.CustodyWithoutTPM(sbLine))
		if !lines.Scan() {
			return "", errors.New("init: the console closed at the protection step")
		}
		return keycustody.ModeKeyfile, nil
	}
	for {
		_, _ = fmt.Fprint(d.out, screens.CustodyWithTPM(sbLine))
		if !lines.Scan() {
			return "", errors.New("init: the console closed at the protection step")
		}
		if m, ok := screens.CustodyChoice(lines.Text()); ok {
			return keycustody.Mode(m), nil
		}
	}
}
