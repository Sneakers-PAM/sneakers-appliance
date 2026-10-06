// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package fixtures

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
)

// Section is one named section of a stub PE image.
type Section struct {
	Name string
	Data []byte
}

// PE returns a minimal PE32+ EFI application with the given sections, the
// shape of a UKI (or of systemd-boot with one .text section). It doesn't
// run; it parses with debug/pe and signs with Authenticode like the real
// thing.
func PE(t testing.TB, sections ...Section) []byte {
	t.Helper()
	const (
		fileAlign    = 0x200
		sectAlign    = 0x1000
		peOffset     = 0x80
		optHeaderLen = 240
	)
	align := func(n, a int) int { return (n + a - 1) / a * a }
	headers := align(peOffset+4+20+optHeaderLen+40*len(sections), fileAlign)

	var raw bytes.Buffer
	type placed struct {
		rva, rawOff, rawLen, virtLen int
	}
	places := make([]placed, len(sections))
	rva := sectAlign
	for i, s := range sections {
		rawLen := align(len(s.Data), fileAlign)
		places[i] = placed{rva: rva, rawOff: headers + raw.Len(), rawLen: rawLen, virtLen: len(s.Data)}
		raw.Write(s.Data)
		raw.Write(make([]byte, rawLen-len(s.Data)))
		rva += align(max(len(s.Data), 1), sectAlign)
	}
	sizeOfImage := rva

	var b bytes.Buffer
	dos := make([]byte, peOffset)
	copy(dos, "MZ")
	binary.LittleEndian.PutUint32(dos[0x3c:], peOffset)
	b.Write(dos)
	b.WriteString("PE\x00\x00")
	u32 := func(n int) uint32 {
		if n < 0 || n > math.MaxUint32 {
			t.Fatalf("PE field %d out of range", n)
		}
		return uint32(n) // #nosec G115 -- bounds checked above
	}
	w := func(v any) {
		if err := binary.Write(&b, binary.LittleEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	// COFF header: x86-64, sections, no symbols, optional header size,
	// executable image.
	w(uint16(0x8664))
	w(uint16(u32(len(sections)) & 0xffff))
	w(uint32(0))
	w(uint32(0))
	w(uint32(0))
	w(uint16(optHeaderLen))
	w(uint16(0x0022))
	// Optional header, PE32+.
	w(uint16(0x20b))
	w(uint8(0))
	w(uint8(0))
	w(uint32(0)) // SizeOfCode
	w(uint32(0)) // SizeOfInitializedData
	w(uint32(0)) // SizeOfUninitializedData
	w(uint32(sectAlign))
	w(uint32(sectAlign))
	w(uint64(0x10000000))
	w(uint32(sectAlign))
	w(uint32(fileAlign))
	w([6]uint16{})      // OS, image and subsystem versions
	w(uint32(0))        // Win32VersionValue
	w(u32(sizeOfImage)) // SizeOfImage
	w(u32(headers))     // SizeOfHeaders
	w(uint32(0))        // CheckSum
	w(uint16(10))       // Subsystem: EFI application
	w(uint16(0))        // DllCharacteristics
	w([4]uint64{0x100000, 0x1000, 0x100000, 0x1000})
	w(uint32(0))    // LoaderFlags
	w(uint32(16))   // NumberOfRvaAndSizes
	w([32]uint32{}) // data directories, the certificate table (4) empty
	for i, s := range sections {
		var name [8]byte
		copy(name[:], s.Name)
		w(name)
		w(u32(places[i].virtLen))
		w(u32(places[i].rva))
		w(u32(places[i].rawLen))
		w(u32(places[i].rawOff))
		w(uint32(0))
		w(uint32(0))
		w(uint16(0))
		w(uint16(0))
		w(uint32(0x40000040)) // initialized data, readable
	}
	b.Write(make([]byte, headers-b.Len()))
	b.Write(raw.Bytes())
	return b.Bytes()
}
