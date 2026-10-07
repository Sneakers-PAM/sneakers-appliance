// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/reaper"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/secureboot"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/tpm"
)

const mkfsExt4 = "/usr/sbin/mkfs.ext4"

// keyslotCost is the state volumes' keyslot cost. The key is 256 random
// bits, not a passphrase, so a costlier Argon2id buys nothing and would
// only slow every boot (and a Pi's more).
var keyslotCost = []string{"--pbkdf-memory", "65536", "--pbkdf-parallel", "1", "--iter-time", "200"}

// reaperRunner runs a tool through init's reaper, which collects every
// child's exit: os/exec's own wait would race it and fail with ECHILD.
type reaperRunner struct{ binary string }

// Run runs the tool with args, stdin as its input.
func (x reaperRunner) Run(ctx context.Context, stdin io.Reader, args ...string) ([]byte, []byte, error) {
	return reaper.NewReaper().Output(ctx, stdin, append([]string{x.binary}, args...))
}

// openTPM opens and provisions the TPM, or returns nil when the box has
// none (or it doesn't answer): key-file custody is then the only choice.
func openTPM(lg log.Logger) *tpm.TPM {
	t, err := tpm.Open("")
	if err != nil {
		lg.Info("init: no TPM", log.F("error", err.Error()))
		return nil
	}
	if err := t.ProvisionSRK(); err != nil {
		lg.Warn("init: the TPM doesn't provision its storage key; treating the box as having none", log.F("error", err.Error()))
		_ = t.Close()
		return nil
	}
	return t
}

// newCustody is the custody over the boot disk dev, and whether there's a
// TPM.
func newCustody(dev string, espOK bool, lg log.Logger) (*keycustody.Custody, bool) {
	d := keycustody.Deps{
		Disk: &keycustody.BootDisk{
			Path:       dev,
			Cryptsetup: reaperRunner{binary: cryptsetup},
			Mounter:    keycustody.Ext4{MkfsRunner: reaperRunner{binary: mkfsExt4}},
			PBKDFArgs:  keyslotCost,
		},
		ClearESPChoice: func() error {
			if !espOK {
				return nil
			}
			err := os.Remove(filepath.Join(espMount, secureboot.ChoiceFile))
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		},
	}
	t := openTPM(lg)
	if t != nil {
		d.TPM = t
	}
	return keycustody.New(d), t != nil
}
