// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package secureboot reads the firmware's Secure Boot state and enrols the
// org keys from Setup Mode (spec 1 Section 2.5).
package secureboot

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// GUIDs of the variables read and written, in text form.
const (
	GlobalGUID   = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
	SecurityGUID = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
)

// ErrNotFound reports a variable the firmware doesn't have.
var ErrNotFound = errors.New("secureboot: no such variable")

// Vars is the UEFI variable store, as efivarfs exposes it. Get returns the
// attributes and the data; Write sets a variable from an authenticated
// payload (EFI_VARIABLE_AUTHENTICATION_2 followed by the data).
type Vars interface {
	Get(name, guid string) (attrs uint32, data []byte, err error)
	Write(name, guid string, attrs uint32, payload []byte) error
}

// Efivarfs is the real store at Dir (normally /sys/firmware/efi/efivars).
type Efivarfs struct{ Dir string }

// DefaultEfivarfs is where init mounts efivarfs.
const DefaultEfivarfs = "/sys/firmware/efi/efivars"

func (e Efivarfs) path(name, guid string) string { return filepath.Join(e.Dir, name+"-"+guid) }

// Present reports whether efivarfs is mounted at Dir.
func (e Efivarfs) Present() bool {
	st, err := os.Stat(e.Dir)
	return err == nil && st.IsDir()
}

// Get reads one variable.
func (e Efivarfs) Get(name, guid string) (uint32, []byte, error) {
	b, err := os.ReadFile(e.path(name, guid))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil, ErrNotFound
	}
	if err != nil {
		return 0, nil, err
	}
	if len(b) < 4 {
		return 0, nil, fmt.Errorf("secureboot: %s is %d bytes", name, len(b))
	}
	return binary.LittleEndian.Uint32(b[:4]), b[4:], nil
}

// Write writes the attributes and payload in a single write, as efivarfs
// requires, clearing the immutable flag efivarfs sets on existing files.
func (e Efivarfs) Write(name, guid string, attrs uint32, payload []byte) error {
	p := e.path(name, guid)
	if f, err := os.Open(p); err == nil { // #nosec G304 -- a fixed variable name under efivarfs
		clearImmutable(f)
		_ = f.Close()
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE, 0o644) // #nosec G302 G304 -- efivarfs fixes the mode; a fixed variable name
	if err != nil {
		return err
	}
	buf := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint32(buf, attrs)
	copy(buf[4:], payload)
	if _, err := f.Write(buf); err != nil {
		_ = f.Close()
		return fmt.Errorf("secureboot: write %s: %w", name, err)
	}
	return f.Close()
}

func clearImmutable(f *os.File) {
	var flags int
	// FS_IOC_GETFLAGS / FS_IOC_SETFLAGS take an int on Linux.
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.FS_IOC_GETFLAGS, uintptr(unsafe.Pointer(&flags))); e != 0 { // #nosec G103 -- the ioctl's int argument
		return
	}
	const fsImmutableFL = 0x00000010 // FS_IMMUTABLE_FL
	flags &^= fsImmutableFL
	_, _, _ = unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.FS_IOC_SETFLAGS, uintptr(unsafe.Pointer(&flags))) // #nosec G103 -- as above
}

// vendorFor is the GUID of a key variable.
func vendorFor(name string) string {
	if strings.HasPrefix(name, "db") {
		return SecurityGUID
	}
	return GlobalGUID
}
