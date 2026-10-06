// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tpm

import (
	"bytes"
	"crypto/sha1" // #nosec G505 -- the event log's legacy header bank
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
)

type logEvent struct {
	pcr  uint32
	typ  uint32
	data []byte
}

// buildLog writes a crypto-agile log with SHA-1 and SHA-256 banks, each
// event's digests being the hash of its data, as firmware writes them for
// EV_EFI_ACTION and separator events.
func buildLog(t *testing.T, events []logEvent) []byte {
	t.Helper()
	var b bytes.Buffer
	w := func(v any) {
		if err := binary.Write(&b, binary.LittleEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	var spec bytes.Buffer
	spec.WriteString("Spec ID Event03\x00")
	_ = binary.Write(&spec, binary.LittleEndian, uint32(0))
	spec.Write([]byte{0, 2, 0, 2})
	_ = binary.Write(&spec, binary.LittleEndian, uint32(2))
	_ = binary.Write(&spec, binary.LittleEndian, []uint16{algSHA1, 20, algSHA256, 32})
	spec.WriteByte(0)
	w(uint32(0))
	w(uint32(EvNoAction))
	w([20]byte{})
	w(uint32(spec.Len())) // #nosec G115 -- small
	b.Write(spec.Bytes())
	for _, e := range events {
		w(e.pcr)
		w(e.typ)
		w(uint32(2))
		s1 := sha1.Sum(e.data) // #nosec G401 -- the legacy bank, not trusted
		w(uint16(algSHA1))
		b.Write(s1[:])
		s256 := sha256.Sum256(e.data)
		w(uint16(algSHA256))
		b.Write(s256[:])
		w(uint32(len(e.data))) // #nosec G115 -- small
		b.Write(e.data)
	}
	return b.Bytes()
}

func TestReplayPCR4MatchesTheTPM(t *testing.T) {
	sim := openSim(t)
	events := []logEvent{
		{4, EvEFIAction, []byte("Calling EFI Application from Boot Option")},
		{4, EvSeparator, []byte{0, 0, 0, 0}},
		{7, EvSeparator, []byte{0, 0, 0, 0}},
		{4, EvEFIBootServicesApplication, []byte("systemd-boot")},
		{4, EvEFIBootServicesApplication, []byte("the UKI")},
	}
	for _, e := range events {
		if e.pcr == 4 {
			if err := sim.ExtendPCR(4, e.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	live, err := sim.ReadPCRs([]int{4})
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReplayPCR4(buildLog(t, events), nil)
	if err != nil || !bytes.Equal(got[:], live[4]) {
		t.Fatalf("replay %x, the TPM has %x (%v)", got, live[4], err)
	}
}

func TestReplayPCR4WithAReplacedUKI(t *testing.T) {
	sim := openSim(t)
	for _, d := range [][]byte{[]byte("systemd-boot"), []byte("the next UKI")} {
		if err := sim.ExtendPCR(4, d); err != nil {
			t.Fatal(err)
		}
	}
	want, _ := sim.ReadPCRs([]int{4})
	log := buildLog(t, []logEvent{{4, EvEFIBootServicesApplication, []byte("systemd-boot")}, {4, EvEFIBootServicesApplication, []byte("the running UKI")}})
	got, err := ReplayPCR4(log, map[[32]byte][32]byte{sha256.Sum256([]byte("the running UKI")): sha256.Sum256([]byte("the next UKI"))})
	if err != nil || !bytes.Equal(got[:], want[4]) {
		t.Fatalf("predicted %x, the next boot measures %x (%v)", got, want[4], err)
	}
}

func TestReplayRefusesWhatItCantRead(t *testing.T) {
	for name, log := range map[string][]byte{
		"empty":     nil,
		"garbage":   []byte("not a log"),
		"truncated": buildLog(t, []logEvent{{4, EvEFIBootServicesApplication, []byte("x")}})[:80],
		"no apps":   buildLog(t, []logEvent{{4, EvSeparator, []byte{0, 0, 0, 0}}}),
	} {
		if _, err := ReplayPCR4(log, nil); !errors.Is(err, ErrEventLog) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
