// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/screens"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/efiauth"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/secureboot"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
)

func deps(t *testing.T, v secureboot.Vars, choice, typed string) (enrolDeps, *bytes.Buffer, *string) {
	t.Helper()
	k := fixtures.LabKeys(t)
	pk, kek, db := efiauth.X509List(fixtures.Owner, k.PK.Cert.Raw), efiauth.X509List(fixtures.Owner, k.KEK.Cert.Raw), efiauth.X509List(fixtures.Owner, k.DB.Cert.Raw)
	m := secureboot.Material{PK: k.PK.AuthFile(t, "PK", pk), KEK: k.PK.AuthFile(t, "KEK", kek), DB: k.KEK.AuthFile(t, "db", db)}
	var out bytes.Buffer
	recorded := choice
	return enrolDeps{
		vars:      v,
		material:  func() (secureboot.Material, error) { return m, nil },
		choice:    choice,
		setChoice: func(c string) error { recorded = c; return nil },
		platform:  screens.VMware,
		in:        strings.NewReader(typed),
		out:       &out,
		logf:      t.Logf,
	}, &out, &recorded
}

func TestEnrolFromSetupModeAfterEnter(t *testing.T) {
	v := secureboot.NewDirVars(t.TempDir(), true)
	d, out, recorded := deps(t, v, "", "\n")
	got, err := runEnrol(d)
	if err != nil || got != enrolReboot || *recorded != "on" {
		t.Fatalf("%v %v %s", got, err, *recorded)
	}
	if !strings.Contains(out.String(), "Secure Boot keys enrolled") {
		t.Fatalf("screen:\n%s", out)
	}
}

func TestOutsideSetupModeShowsTheStepsAndWritesNothing(t *testing.T) {
	v := secureboot.NewDirVars(t.TempDir(), false)
	d, out, recorded := deps(t, v, "on", "no secure boot\n")
	got, err := runEnrol(d)
	if err != nil || got != enrolReduced || *recorded != "off" {
		t.Fatalf("%v %v %s", got, err, *recorded)
	}
	if !strings.Contains(out.String(), "Delete the PK") {
		t.Fatalf("screen:\n%s", out)
	}
	if _, data, _ := v.Get("PK", secureboot.GlobalGUID); string(data) != "vendor PK" {
		t.Fatal("the vendor PK was touched")
	}
}

func TestTypedNoSecureBootAtTheChoice(t *testing.T) {
	v := secureboot.NewDirVars(t.TempDir(), true)
	d, _, recorded := deps(t, v, "", "maybe\nno secure boot\n")
	if got, err := runEnrol(d); err != nil || got != enrolReduced || *recorded != "off" {
		t.Fatalf("%v %v %s", got, err, *recorded)
	}
}

// Outside Setup Mode the org keys can't be enrolled as the firmware is, so
// Enter alone mustn't pick Secure Boot: it asks again, and nothing is
// recorded until the admin types a choice.
func TestOutsideSetupModeEnterAloneChoosesNothing(t *testing.T) {
	v := secureboot.NewDirVars(t.TempDir(), false)
	d, out, recorded := deps(t, v, "", "\n\nno secure boot\n")
	got, err := runEnrol(d)
	if err != nil || got != enrolReduced || *recorded != "off" {
		t.Fatalf("%v %v %s", got, err, *recorded)
	}
	if n := strings.Count(out.String(), "Enter alone does nothing"); n != 3 {
		t.Fatalf("the choice was shown %d times, want 3 (two bare Enters, then the typed choice):\n%s", n, out)
	}
	if strings.Contains(out.String(), "Press Enter to keep 1") {
		t.Fatalf("the screen still offers Enter for Secure Boot:\n%s", out)
	}
}

func TestOutsideSetupModeTypedOneShowsHowToClearTheKeys(t *testing.T) {
	v := secureboot.NewDirVars(t.TempDir(), false)
	d, out, recorded := deps(t, v, "", "1\nno secure boot\n")
	if got, err := runEnrol(d); err != nil || got != enrolReduced || *recorded != "off" {
		t.Fatalf("%v %v %s", got, err, *recorded)
	}
	if !strings.Contains(out.String(), "Delete the PK") {
		t.Fatalf("screen:\n%s", out)
	}
}

func TestOutsideSetupModeEOFAtTheChoice(t *testing.T) {
	v := secureboot.NewDirVars(t.TempDir(), false)
	d, _, recorded := deps(t, v, "", "\n")
	if _, err := runEnrol(d); err == nil || *recorded != "" {
		t.Fatalf("a closed console after a bare Enter: %v, recorded %q", err, *recorded)
	}
}

// The cursor keys do nothing at the Secure Boot choice: an arrow and Enter
// never pick the default, and a typed answer with a stray key in it is
// still the answer.
func TestCursorKeysAtTheChoiceDoNothing(t *testing.T) {
	v := secureboot.NewDirVars(t.TempDir(), true)
	d, out, recorded := deps(t, v, "", "\x1b[A\n\x1b[C\x1b[D\nno secure\x1b[D boot\n")
	if got, err := runEnrol(d); err != nil || got != enrolReduced || *recorded != "off" {
		t.Fatalf("%v %v %s", got, err, *recorded)
	}
	if strings.Contains(out.String(), "Secure Boot keys enrolled") {
		t.Fatalf("an arrow key picked the default:\n%s", out)
	}
}
