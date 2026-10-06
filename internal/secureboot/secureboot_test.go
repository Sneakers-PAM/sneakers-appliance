// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package secureboot_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/efiauth"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/secureboot"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
)

func labMaterial(t *testing.T) (secureboot.Material, release.Pins) {
	t.Helper()
	k := fixtures.LabKeys(t)
	pk, kek, db := efiauth.X509List(fixtures.Owner, k.PK.Cert.Raw), efiauth.X509List(fixtures.Owner, k.KEK.Cert.Raw), efiauth.X509List(fixtures.Owner, k.DB.Cert.Raw)
	return secureboot.Material{
		PK:  k.PK.AuthFile(t, "PK", pk),
		KEK: k.PK.AuthFile(t, "KEK", kek),
		DB:  k.KEK.AuthFile(t, "db", db),
	}, k.Pins()
}

func writeVar(t *testing.T, dir, name, guid string, data ...byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name+"-"+guid), append([]byte{6, 0, 0, 0}, data...), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestReadDistinguishesNoSecureBootFromSetupMode pins Review Focus 5.
func TestReadDistinguishesNoSecureBootFromSetupMode(t *testing.T) {
	if _, err := secureboot.Read(nil, nil); !codes.Is(err, codes.SBNoEfivarfs) {
		t.Fatalf("no efivarfs: %v", err)
	}
	cases := map[string]struct {
		vars map[string]byte
		want secureboot.State
	}{
		"no SB variables":            {map[string]byte{}, secureboot.State{}},
		"setup mode, SB var missing": {map[string]byte{"SetupMode": 1}, secureboot.State{Supported: true, SetupMode: true}},
		"enforcing":                  {map[string]byte{"SetupMode": 0, "SecureBoot": 1}, secureboot.State{Supported: true, Enforcing: true}},
		"user mode, not enforcing":   {map[string]byte{"SetupMode": 0, "SecureBoot": 0}, secureboot.State{Supported: true}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for n, v := range c.vars {
				writeVar(t, dir, n, secureboot.GlobalGUID, v)
			}
			got, err := secureboot.Read(secureboot.Efivarfs{Dir: dir}, nil)
			if err != nil || got != c.want {
				t.Fatalf("got %+v %v", got, err)
			}
		})
	}
}

func TestEnrolFromSetupModeEndsOrgOnly(t *testing.T) {
	m, pins := labMaterial(t)
	v := secureboot.NewDirVars(t.TempDir(), true)
	if err := secureboot.Enrol(v, m, t.Logf); err != nil {
		t.Fatal(err)
	}
	v.Reboot(true)
	st, err := secureboot.Read(v, &pins)
	if err != nil || st.SetupMode || !st.Enforcing || !st.OrgOnly {
		t.Fatalf("not enrolled: %+v %v", st, err)
	}
}

// TestEnrolResumesAfterPowerCutBeforePK pins Review Focus 2.
func TestEnrolResumesAfterPowerCutBeforePK(t *testing.T) {
	m, pins := labMaterial(t)
	v := secureboot.NewDirVars(t.TempDir(), true)
	v.FailAfter("db")
	if err := secureboot.Enrol(v, m, t.Logf); !codes.Is(err, codes.SBEnrolFailed) {
		t.Fatalf("the cut write must fail: %v", err)
	}
	if st, _ := secureboot.Read(v, nil); !st.SetupMode {
		t.Fatal("still in Setup Mode after the cut")
	}
	v.FailAfter("")
	if err := secureboot.Enrol(v, m, t.Logf); err != nil {
		t.Fatal(err)
	}
	st, _ := secureboot.Read(v, &pins)
	if st.SetupMode || !st.OrgOnly {
		t.Fatalf("not enrolled: %+v", st)
	}
}

func TestEnrolOutsideSetupModeWritesNothing(t *testing.T) {
	m, _ := labMaterial(t)
	dir := t.TempDir()
	v := secureboot.NewDirVars(dir, false)
	before, _ := os.ReadDir(dir)
	if err := secureboot.Enrol(v, m, t.Logf); !codes.Is(err, codes.SBNotSetupMode) {
		t.Fatalf("got %v", err)
	}
	after, _ := os.ReadDir(dir)
	if len(before) != len(after) {
		t.Fatal("something was written outside Setup Mode")
	}
	if _, data, _ := v.Get("PK", secureboot.GlobalGUID); string(data) != "vendor PK" {
		t.Fatal("the vendor PK was touched")
	}
}

func TestOrgOnlyRefusesAnExtraDBEntry(t *testing.T) {
	m, pins := labMaterial(t)
	k := fixtures.LabKeys(t)
	db := append(efiauth.X509List(fixtures.Owner, k.DB.Cert.Raw), efiauth.X509List(fixtures.Owner, k.RogueDB.Cert.Raw)...)
	m.DB = k.KEK.AuthFile(t, "db", db)
	v := secureboot.NewDirVars(t.TempDir(), true)
	if err := secureboot.Enrol(v, m, t.Logf); err != nil {
		t.Fatal(err)
	}
	if ok, err := secureboot.OrgOnly(v, pins); err != nil || ok {
		t.Fatalf("a rogue db entry must not count as org-only (%v)", err)
	}
}

func TestDirVarsRefusesWritesOutsideSetupMode(t *testing.T) {
	m, _ := labMaterial(t)
	v := secureboot.NewDirVars(t.TempDir(), false)
	if err := v.Write("db", secureboot.SecurityGUID, efiauth.Attributes, m.DB); !errors.Is(err, secureboot.ErrSecurityViolation) {
		t.Fatalf("got %v", err)
	}
}

func TestChoiceOnTheESP(t *testing.T) {
	esp := t.TempDir()
	if c, err := secureboot.ReadChoice(esp); err != nil || c != "" {
		t.Fatalf("%q %v", c, err)
	}
	if err := secureboot.WriteChoice(esp, secureboot.ChoiceOff); err != nil {
		t.Fatal(err)
	}
	if c, _ := secureboot.ReadChoice(esp); c != secureboot.ChoiceOff {
		t.Fatalf("read %q", c)
	}
	if err := secureboot.WriteChoice(esp, "maybe"); err == nil {
		t.Fatal("bad choice written")
	}
}

func TestLoadMaterialFromTheESP(t *testing.T) {
	m, _ := labMaterial(t)
	esp := t.TempDir()
	dir := filepath.Join(esp, secureboot.KeysDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for n, b := range map[string][]byte{"PK": m.PK, "KEK": m.KEK, "db": m.DB} {
		if err := os.WriteFile(filepath.Join(dir, n+".auth"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := secureboot.LoadMaterial(os.DirFS(esp))
	if err != nil || string(got.PK) != string(m.PK) {
		t.Fatal(err)
	}
}
