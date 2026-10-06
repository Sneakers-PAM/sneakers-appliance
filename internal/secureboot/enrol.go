// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package secureboot

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/efiauth"
)

// Material is the signed enrolment material, as the kit puts it on the ESP
// at loader/keys/sneakers/.
type Material struct {
	PK, KEK, DB []byte // the .auth files
}

// KeysDir is the material's directory on the ESP.
const KeysDir = "loader/keys/sneakers"

// LoadMaterial reads the .auth files from the ESP.
func LoadMaterial(esp fs.FS) (Material, error) {
	var m Material
	for _, f := range []struct {
		name string
		dst  *[]byte
	}{{"PK", &m.PK}, {"KEK", &m.KEK}, {"db", &m.DB}} {
		b, err := fs.ReadFile(esp, KeysDir+"/"+f.name+".auth")
		if err != nil {
			return Material{}, codes.New(codes.SBEnrolFailed, "the ESP has no %s.auth: %v", f.name, err)
		}
		*f.dst = b
	}
	return m, nil
}

// Enrol writes db, KEK and then PK through the variable store, but only in
// Setup Mode: outside it nothing is written and the error is
// SB_NOT_SETUP_MODE, so the console shows the platform's clear-the-keys
// steps again (spec 1 Section 2.5). Every write is read back.
//
// A variable that already holds its new value is skipped, so a run cut off
// by a power loss (say after db, before PK) finishes on the next boot:
// db is left alone and KEK and PK are written. PK goes last because writing
// it ends Setup Mode.
func Enrol(v Vars, m Material, logf func(format string, args ...any)) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	st, err := Read(v, nil)
	if err != nil {
		return err
	}
	if !st.SetupMode {
		return codes.New(codes.SBNotSetupMode, "the firmware isn't in Setup Mode; nothing was written")
	}
	for _, step := range []struct {
		name string
		auth []byte
	}{{"db", m.DB}, {"KEK", m.KEK}, {"PK", m.PK}} {
		a, err := efiauth.ParseAuth(step.auth)
		if err != nil {
			return codes.New(codes.SBEnrolFailed, "%s.auth: %v", step.name, err)
		}
		guid := vendorFor(step.name)
		if _, cur, err := v.Get(step.name, guid); err == nil && bytes.Equal(cur, a.Data) {
			logf("secureboot: %s already enrolled, skipped", step.name)
			continue
		} else if err != nil && !errors.Is(err, ErrNotFound) {
			return codes.New(codes.SBEnrolFailed, "read %s: %v", step.name, err)
		}
		if err := v.Write(step.name, guid, efiauth.Attributes, step.auth); err != nil {
			return codes.New(codes.SBEnrolFailed, "write %s: %v", step.name, err)
		}
		if _, cur, err := v.Get(step.name, guid); err != nil || !bytes.Equal(cur, a.Data) {
			return codes.New(codes.SBEnrolFailed, "%s didn't read back as written", step.name)
		}
		logf("secureboot: %s enrolled", step.name)
	}
	return nil
}

// The admin's Secure Boot choice, kept on the ESP until first boot fixes it
// in the LUKS2 header.
const (
	ChoiceFile = "loader/sneakers/secure-boot"
	ChoiceOn   = "on"
	ChoiceOff  = "off"
)

// ReadChoice returns "on", "off" or "" (not chosen yet) from the ESP
// mounted at espDir.
func ReadChoice(espDir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(espDir, ChoiceFile)) // #nosec G304 -- a fixed path on the mounted ESP
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	switch c := strings.TrimSpace(string(b)); c {
	case ChoiceOn, ChoiceOff:
		return c, nil
	default:
		return "", fmt.Errorf("secureboot: %s holds %q", ChoiceFile, c)
	}
}

// WriteChoice records the choice on the ESP, durably.
func WriteChoice(espDir, choice string) error {
	if choice != ChoiceOn && choice != ChoiceOff {
		return fmt.Errorf("secureboot: choice %q", choice)
	}
	p := filepath.Join(espDir, ChoiceFile)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	tmp := p + ".new"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- a fixed path on the mounted ESP
	if err != nil {
		return err
	}
	if _, err := f.WriteString(choice + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
