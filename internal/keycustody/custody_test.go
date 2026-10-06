// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package keycustody_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/disk"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/luks"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/secureboot"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/tpm"
)

var ctx = context.Background()

// fileVolume is a real LUKS2 volume in a file. Unlock checks the key with
// cryptsetup's --test-passphrase instead of opening a mapping, which needs
// root.
type fileVolume struct {
	*luks.Device
	unlocked int
}

func (v *fileVolume) Unlock(ctx context.Context, key []byte, _ bool) error {
	if err := v.TestKey(ctx, key); err != nil {
		return err
	}
	v.unlocked++
	return nil
}

// fileDisk holds the volumes in files under one directory, as a boot disk
// holds them in partitions.
type fileDisk struct {
	dir     string
	created []disk.Partition
}

func (d *fileDisk) Size() int64  { return 100 * disk.GiB }
func (d *fileDisk) Arch() string { return "amd64" }

func (d *fileDisk) volumes() (keycustody.Volume, keycustody.Volume, keycustody.KeyfileStore) {
	mk := func(name string) *fileVolume {
		return &fileVolume{Device: &luks.Device{Path: filepath.Join(d.dir, name), Runner: &luks.ExecRunner{},
			PBKDFArgs: []string{"--pbkdf-memory", "32768", "--pbkdf-parallel", "1", "--iter-time", "50"}}}
	}
	return mk("state"), mk("backup"), keycustody.FileKeyfile{Path: filepath.Join(d.dir, "keyfile")}
}

func (d *fileDisk) Create(_ context.Context, plan []disk.Partition) (keycustody.Volume, keycustody.Volume, keycustody.KeyfileStore, error) {
	d.created = plan
	for _, name := range []string{"state", "backup", "keyfile"} {
		f, err := os.Create(filepath.Join(d.dir, name)) // #nosec G304 -- the test's own files
		if err != nil {
			return nil, nil, nil, err
		}
		if err := f.Truncate(32 << 20); err != nil {
			return nil, nil, nil, err
		}
		_ = f.Close()
	}
	s, b, k := d.volumes()
	return s, b, k, nil
}

func (d *fileDisk) Open(context.Context) (keycustody.Volume, keycustody.Volume, keycustody.KeyfileStore, error) {
	s, b, k := d.volumes()
	return s, b, k, nil
}

func needCryptsetup(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("cryptsetup"); err != nil {
		if os.Getenv("SNEAKERS_REQUIRE_TOOLS") != "" {
			t.Fatal("cryptsetup isn't installed and SNEAKERS_REQUIRE_TOOLS is set")
		}
		t.Skip("cryptsetup isn't installed; CI installs it")
	}
}

func simTPM(t *testing.T) *tpm.TPM {
	t.Helper()
	sim, err := tpm.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sim.Close() })
	if err := sim.ProvisionSRK(); err != nil {
		t.Fatal(err)
	}
	return sim
}

func TestInitializeRefusesTPMWithoutTPM(t *testing.T) {
	kc := keycustody.New(keycustody.Deps{TPM: nil, Disk: &fileDisk{dir: t.TempDir()}})
	if err := kc.Initialize(ctx, keycustody.ModeTPM, keycustody.SBOn); !codes.Is(err, codes.KeyCustodyNoTPM) {
		t.Fatalf("want KEYCUSTODY_NO_TPM, got %v", err)
	}
}

func TestKeyfileModeAndChoiceSurviveAReboot(t *testing.T) {
	needCryptsetup(t)
	d := &fileDisk{dir: t.TempDir()}
	cleared := false
	kc := keycustody.New(keycustody.Deps{Disk: d, ClearESPChoice: func() error { cleared = true; return nil }})
	if err := kc.Initialize(ctx, keycustody.ModeKeyfile, keycustody.SBOff); err != nil {
		t.Fatal(err)
	}
	if !cleared {
		t.Fatal("the ESP choice must be cleared once the header holds it")
	}
	if d.created[0].Label != disk.LabelKeyfile {
		t.Fatalf("key-file mode plans the key-file partition first: %+v", d.created)
	}
	if err := kc.Initialize(ctx, keycustody.ModeKeyfile, keycustody.SBOff); !codes.Is(err, codes.KeyCustodyInvalid) {
		t.Fatalf("a second Initialize: %v", err)
	}
	// The next boot: a fresh custody reads the header and unlocks.
	again := keycustody.New(keycustody.Deps{Disk: d})
	h, err := again.Load(ctx)
	if err != nil || h.Mode != keycustody.ModeKeyfile || h.SecureBoot != keycustody.SBOff {
		t.Fatalf("header %+v %v", h, err)
	}
	if err := again.Unlock(ctx); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d.dir, "keyfile"), make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := keycustody.New(keycustody.Deps{Disk: d}).Unlock(ctx); !codes.Is(err, codes.KeyCustodyLocked) {
		t.Fatalf("a wiped key file must leave the state locked: %v", err)
	}
}

func TestTPMModeSealsToPCR7And11(t *testing.T) {
	needCryptsetup(t)
	sim := simTPM(t)
	d := &fileDisk{dir: t.TempDir()}
	if err := keycustody.New(keycustody.Deps{TPM: sim, Disk: d}).Initialize(ctx, keycustody.ModeTPM, keycustody.SBOn); err != nil {
		t.Fatal(err)
	}
	if d.created[0].Label != disk.LabelState {
		t.Fatalf("TPM mode has no key-file partition: %+v", d.created)
	}
	s, _, _ := d.volumes()
	toks, _ := s.Tokens(ctx)
	found := false
	for _, raw := range toks {
		if tok, err := luks.ParseTPM2Token(raw); err == nil {
			found = len(tok.PCRs) == 2 && tok.PCRs[0] == 7 && tok.PCRs[1] == 11
		}
	}
	if !found {
		t.Fatal("no PCR 7+11 copy")
	}
	if err := keycustody.New(keycustody.Deps{TPM: sim, Disk: d}).Unlock(ctx); err != nil {
		t.Fatal(err)
	}
	if err := sim.ExtendPCR(7, []byte("someone changed the Secure Boot policy")); err != nil {
		t.Fatal(err)
	}
	if err := keycustody.New(keycustody.Deps{TPM: sim, Disk: d}).Unlock(ctx); !codes.Is(err, codes.KeyCustodyLocked) {
		t.Fatalf("a changed PCR 7 must lock the state: %v", err)
	}
}

func TestTPMModeWithSecureBootOffSealsToPCR4And11(t *testing.T) {
	needCryptsetup(t)
	sim := simTPM(t)
	d := &fileDisk{dir: t.TempDir()}
	if err := keycustody.New(keycustody.Deps{TPM: sim, Disk: d}).Initialize(ctx, keycustody.ModeTPM, keycustody.SBOff); err != nil {
		t.Fatal(err)
	}
	s, _, _ := d.volumes()
	toks, _ := s.Tokens(ctx)
	for _, raw := range toks {
		if tok, err := luks.ParseTPM2Token(raw); err == nil && (tok.PCRs[0] != 4 || tok.PCRs[1] != 11) {
			t.Fatalf("PCRs %v", tok.PCRs)
		}
	}
}

func TestProtectionReasons(t *testing.T) {
	cases := []struct {
		sb     secureboot.State
		choice keycustody.SB
		mode   keycustody.Mode
		want   keycustody.Protection
	}{
		{secureboot.State{Supported: true, Enforcing: true, OrgOnly: true}, keycustody.SBOn, keycustody.ModeTPM, keycustody.Full()},
		{secureboot.State{Supported: true}, keycustody.SBOff, keycustody.ModeTPM, keycustody.Reduced(keycustody.ReasonSecureBootOff)},
		{secureboot.State{Supported: false}, keycustody.SBOff, keycustody.ModeKeyfile, keycustody.Reduced(keycustody.ReasonNoSecureBootFirmware)},
		{secureboot.State{Supported: true, Enforcing: true, OrgOnly: true}, keycustody.SBOn, keycustody.ModeKeyfile, keycustody.Reduced(keycustody.ReasonNoTPM)},
		{secureboot.State{Supported: true, Enforcing: true}, keycustody.SBOn, keycustody.ModeTPM, keycustody.Reduced(keycustody.ReasonSecureBootOff)},
	}
	for _, c := range cases {
		if got := keycustody.ProtectionFor(c.sb, c.choice, c.mode); got != c.want {
			t.Errorf("%+v %s %s: got %+v", c.sb, c.choice, c.mode, got)
		}
	}
}
