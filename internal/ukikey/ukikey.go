// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package ukikey carries the box's update key (the age identity a .bin's
// payload is encrypted to) inside the signed UKI, as its own PE section.
//
// The release workflow's sign job adds the section to the unsigned UKI just
// before it signs it, so the build job never holds the key; a lab build does
// the same with its lab key. On the box the key is read from the UKI that
// booted, into memory only: it's never written anywhere.
//
// The encryption protects the package in transit and on download mirrors.
// Anyone holding a genuine image can read the key out of it; a package's
// authenticity comes from its signature, never from the encryption.
package ukikey

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
	"unicode/utf16"

	"filippo.io/age"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/imageupgrade"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/secureboot"
)

// Section is the PE section that holds the key. systemd-stub doesn't measure
// it (internal/ukipcr skips it too).
const Section = ".updkey"

// LoaderGUID is systemd-boot's vendor GUID; LoaderEntrySelected under it
// names the entry that booted.
const LoaderGUID = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"

// maxKey bounds the section: an age X25519 identity is 74 characters.
const maxKey = 4096

// PE32+ header offsets, from the start of the optional header.
const (
	optSectionAlign = 32
	optFileAlign    = 36
	optSizeOfImage  = 56
	optSizeOfHeader = 60
	sectionHeader   = 40
	initDataRead    = 0x40000040
)

// Embed returns uki with the update key in keyFile (an age identity file,
// comments allowed) added as the Section. It refuses a signed image (the
// signature must cover the key), an image that already has a key, and a
// file that isn't exactly one X25519 identity.
func Embed(uki, keyFile []byte) ([]byte, error) {
	id, err := parse(keyFile)
	if err != nil {
		return nil, err
	}
	f, err := pe.NewFile(bytes.NewReader(uki))
	if err != nil {
		return nil, fmt.Errorf("ukikey: not a PE image: %w", err)
	}
	defer func() { _ = f.Close() }()
	opt, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		return nil, errors.New("ukikey: not a PE32+ image")
	}
	if len(opt.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_SECURITY {
		if d := opt.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]; d.VirtualAddress != 0 || d.Size != 0 {
			return nil, errors.New("ukikey: the image is already signed; add the key before signing")
		}
	}
	for _, s := range f.Sections {
		if s.Name == Section {
			return nil, fmt.Errorf("ukikey: the image already has a %s section", Section)
		}
	}

	peOff := int(binary.LittleEndian.Uint32(uki[0x3c:]))
	coff := peOff + 4
	optOff := coff + 20
	table := optOff + int(f.SizeOfOptionalHeader)
	end := table + sectionHeader*len(f.Sections)
	if end+sectionHeader > int(opt.SizeOfHeaders) || !zero(uki[end:end+sectionHeader]) {
		return nil, errors.New("ukikey: no room in the headers for another section")
	}

	data := []byte(id.String())
	fileAlign, sectAlign := int(opt.FileAlignment), int(opt.SectionAlignment)
	rawOff := alignUp(len(uki), fileAlign)
	rawLen := alignUp(len(data), fileAlign)
	rva := int(opt.SizeOfImage)

	out := make([]byte, rawOff+rawLen)
	copy(out, uki)
	copy(out[rawOff:], data)
	hdr := out[end : end+sectionHeader]
	copy(hdr[0:8], Section)
	le := binary.LittleEndian
	le.PutUint32(hdr[8:], uint32(len(data))) // #nosec G115 -- under maxKey
	le.PutUint32(hdr[12:], uint32(rva))      // #nosec G115 -- from a uint32 field
	le.PutUint32(hdr[16:], uint32(rawLen))   // #nosec G115 -- under maxKey, aligned
	le.PutUint32(hdr[20:], uint32(rawOff))   // #nosec G115 -- bounded by the PE's own size
	le.PutUint32(hdr[36:], initDataRead)
	le.PutUint16(out[coff+2:], uint16(len(f.Sections)+1))                                // #nosec G115 -- a PE holds at most 96 sections
	le.PutUint32(out[optOff+optSizeOfImage:], uint32(rva+alignUp(len(data), sectAlign))) // #nosec G115 -- as above
	return out, nil
}

// Identity reads the update key out of a UKI. A UKI without one is
// UPGRADE_DECRYPT: the box has no key to decrypt with.
func Identity(uki io.ReaderAt) (*age.X25519Identity, error) {
	f, err := pe.NewFile(uki)
	if err != nil {
		return nil, codes.New(codes.UpgradeDecrypt, "the running UKI isn't a PE image: %v", err)
	}
	defer func() { _ = f.Close() }()
	s := f.Section(Section)
	if s == nil {
		return nil, codes.New(codes.UpgradeDecrypt, "the running UKI carries no update key")
	}
	if s.VirtualSize > maxKey || s.VirtualSize > s.Size {
		return nil, codes.New(codes.UpgradeDecrypt, "the UKI's update key section is %d bytes", s.VirtualSize)
	}
	b := make([]byte, s.VirtualSize)
	if _, err := s.ReadAt(b, 0); err != nil {
		return nil, codes.New(codes.UpgradeDecrypt, "the UKI's update key can't be read: %v", err)
	}
	id, err := age.ParseX25519Identity(string(b))
	if err != nil {
		return nil, codes.New(codes.UpgradeDecrypt, "the UKI's update key isn't an age X25519 identity")
	}
	return id, nil
}

// Running reads the update key out of the UKI that booted: the entry
// systemd-boot names in LoaderEntrySelected, found under EFI/Linux on the ESP
// whatever its boot counter says now.
func Running(vars secureboot.Vars, esp fs.FS) (*age.X25519Identity, error) {
	_, raw, err := vars.Get("LoaderEntrySelected", LoaderGUID)
	if err != nil {
		return nil, codes.New(codes.UpgradeDecrypt, "the booted entry isn't known (LoaderEntrySelected: %v)", err)
	}
	sel, ok := imageupgrade.ParseEntry(utf16z(raw))
	if !ok {
		return nil, codes.New(codes.UpgradeDecrypt, "the booted entry %q isn't an appliance UKI", utf16z(raw))
	}
	names, err := fs.ReadDir(esp, imageupgrade.UKIDir)
	if err != nil {
		return nil, codes.New(codes.UpgradeDecrypt, "the ESP can't be listed: %v", err)
	}
	for _, n := range names {
		e, ok := imageupgrade.ParseEntry(n.Name())
		if !ok || e.Version != sel.Version {
			continue
		}
		b, err := fs.ReadFile(esp, path.Join(imageupgrade.UKIDir, n.Name()))
		if err != nil {
			return nil, codes.New(codes.UpgradeDecrypt, "the booted UKI can't be read: %v", err)
		}
		return Identity(bytes.NewReader(b))
	}
	return nil, codes.New(codes.UpgradeDecrypt, "the booted UKI %s isn't on the ESP", sel.Name)
}

func parse(keyFile []byte) (*age.X25519Identity, error) {
	ids, err := age.ParseIdentities(bytes.NewReader(keyFile))
	if err != nil {
		return nil, fmt.Errorf("ukikey: the update key: %w", err)
	}
	if len(ids) != 1 {
		return nil, fmt.Errorf("ukikey: the update key file holds %d identities; want one", len(ids))
	}
	x, ok := ids[0].(*age.X25519Identity)
	if !ok {
		return nil, errors.New("ukikey: the update key isn't an age X25519 identity")
	}
	return x, nil
}

func utf16z(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return strings.TrimSpace(string(utf16.Decode(u)))
}

func zero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func alignUp(n, a int) int { return (n + a - 1) / a * a }
