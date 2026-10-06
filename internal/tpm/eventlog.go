// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tpm

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// The TCG PC Client crypto-agile event log, as the firmware leaves it in
// /sys/kernel/security/tpm0/binary_bios_measurements: a SHA-1-format
// header event whose data is the "Spec ID Event03" naming the digest
// algorithms, then TCG_PCR_EVENT2 records carrying one digest per bank.

// Event types the replay cares about.
const (
	EvNoAction                   = 0x00000003
	EvSeparator                  = 0x00000004
	EvEFIBootServicesApplication = 0x80000003
	EvEFIAction                  = 0x80000007
)

const (
	algSHA1   = 0x0004
	algSHA256 = 0x000b
)

// Event is one measured event.
type Event struct {
	PCR    int
	Type   uint32
	SHA256 [sha256.Size]byte
	Data   []byte
}

// ErrEventLog reports a log that can't be read.
var ErrEventLog = errors.New("tpm: unreadable event log")

// ParseEventLog reads a crypto-agile log and returns its SHA-256 events.
func ParseEventLog(b []byte) ([]Event, error) {
	r := bytes.NewReader(b)
	// The header: pcr, type, a SHA-1 digest, size, data.
	var hdr struct {
		PCR, Type uint32
		Digest    [20]byte
		Size      uint32
	}
	if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil || hdr.Type != EvNoAction {
		return nil, fmt.Errorf("%w: no Spec ID header", ErrEventLog)
	}
	spec := make([]byte, hdr.Size)
	if _, err := r.Read(spec); err != nil || !bytes.HasPrefix(spec, []byte("Spec ID Event03\x00")) {
		return nil, fmt.Errorf("%w: not a crypto-agile log", ErrEventLog)
	}
	sizes, err := algSizes(spec)
	if err != nil {
		return nil, err
	}
	if _, ok := sizes[algSHA256]; !ok {
		return nil, fmt.Errorf("%w: the log has no SHA-256 bank", ErrEventLog)
	}
	var out []Event
	for r.Len() > 0 {
		var head struct{ PCR, Type, Count uint32 }
		if err := binary.Read(r, binary.LittleEndian, &head); err != nil {
			return nil, fmt.Errorf("%w: truncated event", ErrEventLog)
		}
		if head.Count > 16 {
			return nil, fmt.Errorf("%w: %d digests in one event", ErrEventLog, head.Count)
		}
		ev := Event{PCR: int(head.PCR), Type: head.Type} // #nosec G115 -- PCR indexes are small
		found := false
		for i := uint32(0); i < head.Count; i++ {
			var alg uint16
			if err := binary.Read(r, binary.LittleEndian, &alg); err != nil {
				return nil, fmt.Errorf("%w: truncated digest", ErrEventLog)
			}
			n, ok := sizes[alg]
			if !ok {
				return nil, fmt.Errorf("%w: digest algorithm %#x isn't in the header", ErrEventLog, alg)
			}
			d := make([]byte, n)
			if _, err := r.Read(d); err != nil {
				return nil, fmt.Errorf("%w: truncated digest", ErrEventLog)
			}
			if alg == algSHA256 {
				copy(ev.SHA256[:], d)
				found = true
			}
		}
		var size uint32
		if err := binary.Read(r, binary.LittleEndian, &size); err != nil || int64(size) > int64(r.Len()) {
			return nil, fmt.Errorf("%w: bad event size", ErrEventLog)
		}
		ev.Data = make([]byte, size)
		if _, err := r.Read(ev.Data); err != nil && size > 0 {
			return nil, fmt.Errorf("%w: truncated event data", ErrEventLog)
		}
		if found && ev.Type != EvNoAction {
			out = append(out, ev)
		}
	}
	return out, nil
}

// algSizes reads the digest sizes from the Spec ID event.
func algSizes(spec []byte) (map[uint16]int, error) {
	// signature[16] platformClass u32 versionMinor u8 versionMajor u8
	// errata u8 uintnSize u8 numberOfAlgorithms u32, then {algId u16, size u16}.
	const off = 16 + 4 + 4
	if len(spec) < off+4 {
		return nil, fmt.Errorf("%w: short Spec ID event", ErrEventLog)
	}
	n := binary.LittleEndian.Uint32(spec[off:])
	if n == 0 || n > 16 || len(spec) < off+4+int(n)*4 {
		return nil, fmt.Errorf("%w: %d algorithms in the Spec ID event", ErrEventLog, n)
	}
	out := map[uint16]int{}
	for i := 0; i < int(n); i++ {
		p := off + 4 + i*4
		out[binary.LittleEndian.Uint16(spec[p:])] = int(binary.LittleEndian.Uint16(spec[p+2:]))
	}
	return out, nil
}

// ReplayPCR returns the SHA-256 value pcr ends at after the events, with
// each event digest found in replace swapped for its replacement: how a
// staged UKI's PCR 4 is predicted from the running boot's log, replacing
// the running loader's, UKI's and kernel's Authenticode digests with the
// new ones.
func ReplayPCR(events []Event, pcr int, replace map[[sha256.Size]byte][sha256.Size]byte) [sha256.Size]byte {
	var v [sha256.Size]byte
	for _, e := range events {
		if e.PCR != pcr {
			continue
		}
		d := e.SHA256
		if r, ok := replace[d]; ok {
			d = r
		}
		h := sha256.New()
		h.Write(v[:])
		h.Write(d[:])
		copy(v[:], h.Sum(nil))
	}
	return v
}

// ReplayPCR4 is ReplayPCR for PCR 4, the boot manager code measurements,
// refusing a log with no EFI application events (nothing to replace means
// the prediction would just be a guess).
func ReplayPCR4(log []byte, replace map[[sha256.Size]byte][sha256.Size]byte) ([sha256.Size]byte, error) {
	events, err := ParseEventLog(log)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	apps := 0
	for _, e := range events {
		if e.PCR == 4 && e.Type == EvEFIBootServicesApplication {
			apps++
		}
	}
	if apps == 0 {
		return [sha256.Size]byte{}, fmt.Errorf("%w: no EFI application was measured into PCR 4", ErrEventLog)
	}
	return ReplayPCR(events, 4, replace), nil
}
