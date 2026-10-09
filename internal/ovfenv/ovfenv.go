// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package ovfenv reads the OVF environment a VMware deployment hands the
// box: the vApp properties the OVA offers (internal/ova), the host name and
// the domain, which vCenter asks for at deploy and writes to an
// ovf-env.xml on an ISO it puts in the VM's CD drive (the iso transport).
// netd takes them as the host name at first boot, while the box has no
// network settings of its own (docs/network.md#the-host-name).
package ovfenv

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf16"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

// The vApp property keys the OVA declares.
const (
	KeyHostname = "hostname"
	KeyDomain   = "domain"
)

// Devices are the CD drives the environment ISO may be in.
var Devices = []string{"/dev/sr0", "/dev/sr1", "/dev/sr2", "/dev/sr3"}

// ErrNone is no environment on any drive: a deployment that set no vApp
// properties, or one that isn't through vCenter.
var ErrNone = errors.New("ovfenv: no OVF environment")

// Env is the environment's properties, key to value.
type Env map[string]string

// Hostname is the host name setting the properties offer: a fully
// qualified host name as it is; a short one joined to the domain; the
// box's own name joined to the domain when only the domain is set. It is
// empty when they make no fully qualified name.
func (e Env) Hostname(own string) string {
	clean := func(s string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".") }
	h, d := clean(e[KeyHostname]), clean(e[KeyDomain])
	switch {
	case strings.Contains(h, "."):
	case h != "" && d != "":
		h += "." + d
	case h == "" && d != "" && own != "":
		h = own + "." + d
	}
	if !network.ValidHostname(h) {
		return ""
	}
	return h
}

// Read reads the environment from the first of devices that holds one.
func Read(devices []string) (Env, error) {
	var errs []error
	for _, dev := range devices {
		f, err := os.Open(dev) // #nosec G304 -- a CD drive from a fixed list
		if err != nil {
			continue
		}
		b, err := isoFile(f, "ovf-env.xml")
		_ = f.Close()
		if errors.Is(err, ErrNone) {
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", dev, err))
			continue
		}
		env, err := parse(b)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", dev, err))
			continue
		}
		return env, nil
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return nil, ErrNone
}

func parse(b []byte) (Env, error) {
	var doc struct {
		Properties []struct {
			Attrs []xml.Attr `xml:",any,attr"`
		} `xml:"PropertySection>Property"`
	}
	if err := xml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("ovfenv: ovf-env.xml doesn't parse: %w", err)
	}
	env := Env{}
	for _, p := range doc.Properties {
		var k, v string
		for _, a := range p.Attrs {
			name := a.Name
			switch name.Local {
			case "key":
				k = a.Value
			case "value":
				v = a.Value
			}
		}
		if k != "" {
			env[k] = v
		}
	}
	return env, nil
}

const (
	sector  = 2048
	maxFile = 1 << 20
)

// isoFile is the file name in the root directory of the ISO 9660 image
// on r, from the primary volume or a Joliet one. Names are matched without
// case, version (";1") or a trailing dot, and with "_" for "-", as strict
// writers rename them.
func isoFile(r io.ReaderAt, name string) ([]byte, error) {
	want := isoName(name)
	vd := make([]byte, sector)
	for i := int64(16); i < 32; i++ {
		if _, err := r.ReadAt(vd, i*sector); err != nil {
			return nil, ErrNone
		}
		if string(vd[1:6]) != "CD001" {
			return nil, ErrNone
		}
		typ := vd[0]
		if typ == 255 {
			break
		}
		if typ != 1 && typ != 2 {
			continue
		}
		joliet := typ == 2 && vd[88] == '%' && vd[89] == '/' && bytes.IndexByte([]byte("@CE"), vd[90]) >= 0
		if typ == 2 && !joliet {
			continue
		}
		root := vd[156:190]
		dir, err := readExtent(r, root)
		if err != nil {
			return nil, err
		}
		for off := 0; off < len(dir); {
			n := int(dir[off])
			if n == 0 {
				off = (off/sector + 1) * sector
				continue
			}
			if off+n > len(dir) || n < 34 {
				break
			}
			rec := dir[off : off+n]
			off += n
			idLen := int(rec[32])
			if 33+idLen > len(rec) || rec[25]&2 != 0 {
				continue
			}
			id := rec[33 : 33+idLen]
			got := string(id)
			if joliet {
				got = ucs2(id)
			}
			if isoName(got) == want {
				return readExtent(r, rec)
			}
		}
	}
	return nil, ErrNone
}

func isoName(s string) string {
	if i := strings.IndexByte(s, ';'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".")
	return strings.ReplaceAll(strings.ToLower(s), "-", "_")
}

func ucs2(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.BigEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

// readExtent reads what a directory record points at, up to maxFile.
func readExtent(r io.ReaderAt, rec []byte) ([]byte, error) {
	extent := int64(binary.LittleEndian.Uint32(rec[2:6]))
	size := int64(binary.LittleEndian.Uint32(rec[10:14]))
	if size > maxFile {
		return nil, fmt.Errorf("ovfenv: an ISO extent of %d bytes is over %d", size, maxFile)
	}
	b := make([]byte, size)
	if _, err := r.ReadAt(b, extent*sector); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("ovfenv: the ISO can't be read: %w", err)
	}
	return b, nil
}
