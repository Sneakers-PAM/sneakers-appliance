// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package keycustody

import (
	"context"
	"fmt"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/luks"
)

// SealForImage adds a sealed copy of the state key for a staged UKI, before
// its ESP entry is written, so the first boot of the new release unlocks.
// With Secure Boot on the copy is sealed to the current PCR 7 and the
// predicted PCR 11. With it off, PCR 4 has to be predicted by replaying the
// firmware's event log with the new UKI's Authenticode digest, which isn't
// in yet, so staging is refused rather than sealed to a guess. Key-file
// mode has nothing to seal.
func (c *Custody) SealForImage(ctx context.Context, ukiSHA string, pcr11 []byte) error {
	if c.header.Mode != ModeTPM {
		return nil
	}
	if c.key == nil {
		return codes.New(codes.KeyCustodyLocked, "the state isn't unlocked")
	}
	if c.header.SecureBoot != SBOn {
		return codes.New(codes.UpgradeUnpredictable, "with Secure Boot off the new release's PCR 4 can't be predicted yet")
	}
	cur, err := c.d.TPM.ReadPCRs([]int{7})
	if err != nil {
		return fmt.Errorf("keycustody: read PCR 7: %w", err)
	}
	priv, pub, err := c.d.TPM.SealToPCRValues(c.key, map[int][]byte{7: cur[7], 11: pcr11})
	if err != nil {
		return fmt.Errorf("keycustody: seal for %s: %w", ukiSHA, err)
	}
	tok, err := luks.BuildTPM2Token(priv, pub, 0, PCRs7And11, nil)
	if err != nil {
		return err
	}
	tok.ImageSHA256 = ukiSHA
	b, err := tok.MarshalJSON()
	if err != nil {
		return err
	}
	toks, err := c.state.Tokens(ctx)
	if err != nil {
		return err
	}
	return c.state.ImportToken(ctx, freeID(toks), b)
}

// Prune drops the sealed copies whose UKI isn't in keep. The copy made at
// install time names no UKI; it's kept while keep holds "".
func (c *Custody) Prune(ctx context.Context, keep []string) error {
	if c.header.Mode != ModeTPM {
		return nil
	}
	want := map[string]bool{}
	for _, k := range keep {
		want[k] = true
	}
	copies, err := tpmCopies(ctx, c.state)
	if err != nil {
		return err
	}
	left := 0
	for _, cp := range copies {
		if want[cp.tok.ImageSHA256] {
			left++
		}
	}
	if left == 0 {
		return codes.New(codes.KeyCustodyInvalid, "pruning would leave no sealed copy")
	}
	for _, cp := range copies {
		if !want[cp.tok.ImageSHA256] {
			if err := c.state.RemoveToken(ctx, cp.id); err != nil {
				return err
			}
		}
	}
	return nil
}
