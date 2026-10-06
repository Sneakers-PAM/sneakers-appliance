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
