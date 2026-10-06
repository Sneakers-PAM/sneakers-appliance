// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package secureboot

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/efiauth"
)

// DirVars is a variable store in a plain directory, for tests: it holds
// variables the way efivarfs shows them and behaves like firmware for the
// key variables. In Setup Mode an authenticated write sets the data after
// the header; writing PK ends Setup Mode. Outside Setup Mode writes are
// refused, as VMware refuses them while its default PK is present.
// SecureBoot changes only on Reboot.
type DirVars struct {
	dir string

	mu        sync.Mutex
	failAfter string
	failing   bool
}

// ErrSecurityViolation is what DirVars returns for a refused write.
var ErrSecurityViolation = errors.New("secureboot: security violation")

// NewDirVars makes a store in dir, in Setup Mode or with some other PK.
func NewDirVars(dir string, setupMode bool) *DirVars {
	d := &DirVars{dir: dir}
	d.set("SetupMode", GlobalGUID, []byte{b(setupMode)})
	d.set("SecureBoot", GlobalGUID, []byte{0})
	if !setupMode {
		d.set("PK", GlobalGUID, []byte("vendor PK"))
	}
	return d
}

// NewDirVarsNoSecureBoot makes a store whose firmware has no Secure Boot.
func NewDirVarsNoSecureBoot(dir string) *DirVars { return &DirVars{dir: dir} }

func b(v bool) byte {
	if v {
		return 1
	}
	return 0
}

// FailAfter makes every write after the named variable's fail, as a power
// cut would; "" clears it.
func (d *DirVars) FailAfter(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.failAfter, d.failing = name, false
}

// Reboot applies the firmware's Secure Boot setting: enforcing when the
// admin enabled it and a PK is enrolled.
func (d *DirVars) Reboot(enabled bool) {
	_, _, err := d.Get("PK", GlobalGUID)
	d.set("SecureBoot", GlobalGUID, []byte{b(enabled && err == nil)})
}

func (d *DirVars) path(name, guid string) string { return filepath.Join(d.dir, name+"-"+guid) }

func (d *DirVars) set(name, guid string, data []byte) {
	buf := make([]byte, 4+len(data))
	binary.LittleEndian.PutUint32(buf, 0x06)
	copy(buf[4:], data)
	_ = os.WriteFile(d.path(name, guid), buf, 0o600)
}

// Get reads a variable.
func (d *DirVars) Get(name, guid string) (uint32, []byte, error) {
	return Efivarfs{Dir: d.dir}.Get(name, guid)
}

// Write applies an authenticated write of a key variable.
func (d *DirVars) Write(name, guid string, attrs uint32, payload []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failing {
		return errors.New("secureboot: power lost")
	}
	if _, sm, err := d.Get("SetupMode", GlobalGUID); err != nil || len(sm) == 0 || sm[0] != 1 {
		return ErrSecurityViolation
	}
	a, err := efiauth.ParseAuth(payload)
	if err != nil {
		return ErrSecurityViolation
	}
	buf := make([]byte, 4+len(a.Data))
	binary.LittleEndian.PutUint32(buf, attrs)
	copy(buf[4:], a.Data)
	if err := os.WriteFile(d.path(name, guid), buf, 0o600); err != nil {
		return err
	}
	if name == "PK" {
		d.set("SetupMode", GlobalGUID, []byte{0})
	}
	if d.failAfter == name {
		d.failing = true
	}
	return nil
}
