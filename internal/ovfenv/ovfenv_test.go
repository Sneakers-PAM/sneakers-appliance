// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package ovfenv_test

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/ovfenv"
)

// envXML is an ovf-env.xml as vCenter writes it.
func envXML(hostname, domain string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<Environment xmlns="http://schemas.dmtf.org/ovf/environment/1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:oe="http://schemas.dmtf.org/ovf/environment/1" xmlns:ve="http://www.vmware.com/schema/ovfenv" oe:id="" ve:vCenterId="vm-1">
   <PlatformSection>
      <Kind>VMware ESXi</Kind>
      <Version>8.0.3</Version>
      <Vendor>VMware, Inc.</Vendor>
      <Locale>en</Locale>
   </PlatformSection>
   <PropertySection>
         <Property oe:key="domain" oe:value="` + domain + `"/>
         <Property oe:key="hostname" oe:value="` + hostname + `"/>
   </PropertySection>
</Environment>
`)
}

// iso is a minimal ISO 9660 image: a primary volume descriptor whose root
// holds one file, named as a strict level-1 writer names ovf-env.xml.
func iso(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	const sector = 2048
	img := make([]byte, 20*sector)
	rec := func(extent, size uint32, flags byte, id []byte) []byte {
		r := make([]byte, 33+len(id)+(len(id)+1)%2)
		r[0] = byte(len(r))
		binary.LittleEndian.PutUint32(r[2:], extent)
		binary.BigEndian.PutUint32(r[6:], extent)
		binary.LittleEndian.PutUint32(r[10:], size)
		binary.BigEndian.PutUint32(r[14:], size)
		r[25] = flags
		r[32] = byte(len(id))
		copy(r[33:], id)
		return r
	}
	pvd := img[16*sector:]
	pvd[0] = 1
	copy(pvd[1:], "CD001")
	pvd[6] = 1
	copy(pvd[156:], rec(18, sector, 2, []byte{0}))
	term := img[17*sector:]
	term[0] = 255
	copy(term[1:], "CD001")
	var root bytes.Buffer
	root.Write(rec(18, sector, 2, []byte{0}))
	root.Write(rec(18, sector, 2, []byte{1}))
	root.Write(rec(19, uint32(len(data)), 0, []byte(name)))
	copy(img[18*sector:], root.Bytes())
	copy(img[19*sector:], data)
	return img
}

func write(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sr0")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The environment is read from the ISO vCenter puts in the CD drive,
// whatever the ISO writer did to the file's name.
func TestTheEnvironmentIsReadFromTheISO(t *testing.T) {
	for _, name := range []string{"OVF_ENV.XML;1", "ovf-env.xml", "OVF-ENV.XML;1"} {
		dev := write(t, iso(t, name, envXML("sneakers01", "example.org")))
		env, err := ovfenv.Read([]string{filepath.Join(t.TempDir(), "sr9"), dev})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if env[ovfenv.KeyHostname] != "sneakers01" || env[ovfenv.KeyDomain] != "example.org" {
			t.Fatalf("%s: %v", name, env)
		}
	}
	if _, err := ovfenv.Read([]string{write(t, iso(t, "README.TXT;1", []byte("x")))}); err != ovfenv.ErrNone {
		t.Fatalf("an ISO with no environment: %v", err)
	}
	if _, err := ovfenv.Read([]string{write(t, make([]byte, 40000))}); err != ovfenv.ErrNone {
		t.Fatalf("a drive with no ISO: %v", err)
	}
}

// The same from an ISO a real writer made with Joliet and Rock Ridge, the
// way vCenter's look.
func TestTheEnvironmentIsReadFromAnXorrisoISO(t *testing.T) {
	x, err := exec.LookPath("xorrisofs")
	if err != nil {
		t.Skip("xorrisofs isn't installed")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ovf-env.xml"), envXML("sneakers01.example.org", ""), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "env.iso")
	if b, err := exec.Command(x, "-quiet", "-J", "-R", "-o", out, dir).CombinedOutput(); err != nil { // #nosec G204 -- the test's own files
		t.Fatalf("%v: %s", err, b)
	}
	env, err := ovfenv.Read([]string{out})
	if err != nil || env[ovfenv.KeyHostname] != "sneakers01.example.org" {
		t.Fatalf("%v %v", env, err)
	}
}

// The host name setting the deployment offers: a full name as it is, a
// short one with the domain, the box's own name with a domain alone, and
// nothing that isn't a fully qualified name.
func TestTheOfferedHostName(t *testing.T) {
	for _, c := range []struct {
		host, domain, want string
	}{
		{"sneakers01.example.org", "", "sneakers01.example.org"},
		{"Sneakers01.Example.org.", "ignored.example", "sneakers01.example.org"},
		{"sneakers01", "example.org", "sneakers01.example.org"},
		{"", "example.org", "sneakers-0a1b2c3d.example.org"},
		{"sneakers01", "", ""},
		{"", "", ""},
		{"bad_name", "example.org", ""},
	} {
		env := ovfenv.Env{ovfenv.KeyHostname: c.host, ovfenv.KeyDomain: c.domain}
		if got := env.Hostname("sneakers-0a1b2c3d"); got != c.want {
			t.Errorf("%q + %q: %q, want %q", c.host, c.domain, got, c.want)
		}
	}
}
