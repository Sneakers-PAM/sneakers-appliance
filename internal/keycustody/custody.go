// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package keycustody holds the state key (spec 1 Section 3.5): one random
// 256-bit key that unlocks the LUKS2 state and backup volumes, kept either
// sealed in the TPM (to PCR 7 and 11 with Secure Boot on, PCR 4 and 11 with
// it off) or in the key-file partition. The mode and the Secure Boot choice
// are fixed at first boot in a LUKS2 header token and read back on every
// boot. There is no boot passphrase and no key derived from the machine's
// identity.
package keycustody

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/disk"
)

// Mode is where the state key is kept.
type Mode string

// The modes.
const (
	ModeTPM     Mode = "tpm"
	ModeKeyfile Mode = "keyfile"
)

// SB is the recorded Secure Boot choice.
type SB string

// The choices.
const (
	SBOn  SB = "on"
	SBOff SB = "off"
)

// KeySize is the state key's length.
const KeySize = 32

// PCR sets the key is sealed to.
var (
	PCRs7And11 = []int{7, 11}
	PCRs4And11 = []int{4, 11}
)

// Sealer is the TPM, as custody uses it.
type Sealer interface {
	SealToPCR(data []byte, pcrs []int) (private, public []byte, err error)
	UnsealWithPCR(private, public []byte, pcrs []int) ([]byte, error)
}

// Volume is one LUKS2 device, as custody uses it.
type Volume interface {
	Format(ctx context.Context, key []byte) error
	IsLUKS(ctx context.Context) bool
	ImportToken(ctx context.Context, id int, tokenJSON []byte) error
	ExportToken(ctx context.Context, id int) ([]byte, error)
	Tokens(ctx context.Context) (map[int][]byte, error)
	RemoveToken(ctx context.Context, id int) error
	// Unlock opens the volume with key and makes its filesystem (first
	// time only) and mounts it.
	Unlock(ctx context.Context, key []byte, mkfs bool) error
}

// Disk is the boot disk: where first boot creates its partitions.
type Disk interface {
	Size() int64
	Arch() string
	// Create makes the planned partitions and returns the state, backup
	// and (when planned) key-file volumes.
	Create(ctx context.Context, plan []disk.Partition) (state, backup Volume, keyfile KeyfileStore, err error)
	// Open returns the volumes of a box set up before.
	Open(ctx context.Context) (state, backup Volume, keyfile KeyfileStore, err error)
}

// KeyfileStore is the key-file partition.
type KeyfileStore interface {
	Write(key []byte) error
	Read() ([]byte, error)
}

// Deps are custody's collaborators. TPM is nil on a box without one.
type Deps struct {
	TPM  Sealer
	Disk Disk
	// Rand fills keys; nil means crypto/rand.
	Rand func([]byte) error
	// ClearESPChoice deletes the ESP's Secure Boot choice file once the
	// header holds it.
	ClearESPChoice func() error
	// SealedDir overrides where sealed items are kept (tests).
	SealedDir string
}

// Custody is the KeyCustody service's state.
type Custody struct {
	d      Deps
	header Header
	state  Volume
	backup Volume
	keyf   KeyfileStore
	key    []byte
}

// New makes a custody over d.
func New(d Deps) *Custody {
	if d.Rand == nil {
		d.Rand = func(b []byte) error { _, err := rand.Read(b); return err }
	}
	return &Custody{d: d}
}

// Initialize runs once, in firstboot: it creates the key-file (key-file
// mode), state and backup partitions to fill the disk, formats state and
// backup as LUKS2 with one new random key, keeps the key in the TPM or the
// key file, records the mode and the Secure Boot choice in the header, and
// unlocks both volumes.
func (c *Custody) Initialize(ctx context.Context, mode Mode, sb SB) error {
	switch mode {
	case ModeTPM:
		if c.d.TPM == nil {
			return codes.New(codes.KeyCustodyNoTPM, "this box has no TPM; choose key-file mode")
		}
	case ModeKeyfile:
	default:
		return codes.New(codes.KeyCustodyInvalid, "custody mode %q", mode)
	}
	if sb != SBOn && sb != SBOff {
		return codes.New(codes.KeyCustodyInvalid, "Secure Boot choice %q", sb)
	}
	if c.header.Mode != "" {
		return codes.New(codes.KeyCustodyInvalid, "custody is already initialized (%s)", c.header.Mode)
	}
	plan, err := disk.FirstBootPlan(c.d.Disk.Size(), disk.InstalledBytes(c.d.Disk.Arch()), c.d.Disk.Arch(), mode == ModeKeyfile)
	if err != nil {
		return codes.Wrap(codes.KeyCustodyInvalid, err)
	}
	state, backup, keyf, err := c.d.Disk.Create(ctx, plan)
	if err != nil {
		return fmt.Errorf("keycustody: create the partitions: %w", err)
	}
	key := make([]byte, KeySize)
	if err := c.d.Rand(key); err != nil {
		return err
	}
	for name, v := range map[string]Volume{"state": state, "backup": backup} {
		if err := v.Format(ctx, key); err != nil {
			return fmt.Errorf("keycustody: format %s: %w", name, err)
		}
	}
	h := Header{Mode: mode, SecureBoot: sb}
	if mode == ModeKeyfile {
		if err := keyf.Write(key); err != nil {
			return fmt.Errorf("keycustody: write the key file: %w", err)
		}
	} else {
		pcrs := PCRs4And11
		if sb == SBOn {
			pcrs = PCRs7And11
		}
		if err := addTPMCopy(ctx, c.d.TPM, state, key, pcrs, ""); err != nil {
			return err
		}
	}
	if err := writeHeader(ctx, state, h); err != nil {
		return err
	}
	for name, v := range map[string]Volume{"state": state, "backup": backup} {
		if err := v.Unlock(ctx, key, true); err != nil {
			return fmt.Errorf("keycustody: unlock %s: %w", name, err)
		}
	}
	if c.d.ClearESPChoice != nil {
		if err := c.d.ClearESPChoice(); err != nil {
			return fmt.Errorf("keycustody: clear the ESP choice: %w", err)
		}
	}
	c.header, c.state, c.backup, c.keyf, c.key = h, state, backup, keyf, key
	return nil
}

// Load reads the header of a box set up before. A box that hasn't run
// Initialize returns KEYCUSTODY_NOT_INITIALIZED.
func (c *Custody) Load(ctx context.Context) (Header, error) {
	state, backup, keyf, err := c.d.Disk.Open(ctx)
	if err != nil {
		return Header{}, codes.Wrap(codes.KeyCustodyNotInitialized, err)
	}
	if !state.IsLUKS(ctx) {
		return Header{}, codes.New(codes.KeyCustodyNotInitialized, "the state volume isn't LUKS2")
	}
	h, err := readHeader(ctx, state)
	if err != nil {
		return Header{}, err
	}
	c.header, c.state, c.backup, c.keyf = h, state, backup, keyf
	return h, nil
}

// Unlock opens state and backup on a later boot: with whichever TPM copy
// unseals, or the key file.
func (c *Custody) Unlock(ctx context.Context) error {
	if c.header.Mode == "" {
		if _, err := c.Load(ctx); err != nil {
			return err
		}
	}
	key, err := c.recoverKey(ctx)
	if err != nil {
		return err
	}
	for name, v := range map[string]Volume{"state": c.state, "backup": c.backup} {
		if err := v.Unlock(ctx, key, false); err != nil {
			return codes.New(codes.KeyCustodyLocked, "the %s volume doesn't open with the recovered key: %v", name, err)
		}
	}
	c.key = key
	return nil
}

func (c *Custody) recoverKey(ctx context.Context) ([]byte, error) {
	if c.header.Mode == ModeKeyfile {
		if c.keyf == nil {
			return nil, codes.New(codes.KeyCustodyLocked, "the key-file partition is missing")
		}
		key, err := c.keyf.Read()
		if err != nil || len(key) != KeySize {
			return nil, codes.New(codes.KeyCustodyLocked, "the key-file partition holds no key")
		}
		return key, nil
	}
	if c.d.TPM == nil {
		return nil, codes.New(codes.KeyCustodyLocked, "the state is sealed to a TPM this box no longer has")
	}
	copies, err := tpmCopies(ctx, c.state)
	if err != nil {
		return nil, err
	}
	for _, cp := range copies {
		key, err := cp.unseal(c.d.TPM)
		if err == nil && len(key) == KeySize {
			return key, nil
		}
	}
	return nil, codes.New(codes.KeyCustodyLocked, "no sealed copy unseals: PCR 7 or 11 (or 4) changed")
}

// Mode returns the fixed custody mode.
func (c *Custody) Mode() Mode { return c.header.Mode }

// Header returns what the LUKS2 header records.
func (c *Custody) Header() Header { return c.header }
