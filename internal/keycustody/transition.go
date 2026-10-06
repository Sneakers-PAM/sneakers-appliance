// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package keycustody

import (
	"bytes"
	"context"
	"fmt"
	"slices"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/secureboot"
)

// SetSecureBoot records the :8443 Secure Boot setting (spec 1 Section 2.7).
// Turning it off adds a copy of the state key sealed to PCR 4 and 11 (the
// firmware's measurement of the loader and UKI) so the next boot, with
// Secure Boot off in the firmware, still unlocks. Turning it on records the
// choice with enrolment pending and keeps the PCR 4 and 11 copy, so the
// boots until the org keys enforce still unlock. Key-file mode records the
// choice only.
func (c *Custody) SetSecureBoot(ctx context.Context, on bool) error {
	if c.key == nil {
		return codes.New(codes.KeyCustodyLocked, "the state isn't unlocked")
	}
	h := c.header
	if on {
		if h.SecureBoot == SBOn {
			return nil
		}
		h.SecureBoot, h.EnrolPending = SBOn, true
	} else {
		if h.SecureBoot == SBOff {
			return nil
		}
		if h.Mode == ModeTPM {
			if err := c.sealCurrent(ctx, PCRs4And11); err != nil {
				return err
			}
		}
		h.SecureBoot, h.EnrolPending = SBOff, false
	}
	if err := writeHeader(ctx, c.state, h); err != nil {
		return err
	}
	c.header = h
	return nil
}

// OnBoot finishes a transition once the firmware shows it took effect. With
// the choice on and the firmware enforcing org-only keys, it seals a copy to
// the new PCR 7 and 11, checks that copy unseals, and only then drops the
// PCR 4 and 11 copies. With the choice off and Secure Boot off in the
// firmware, it drops the PCR 7 and 11 copies. It runs after Unlock.
func (c *Custody) OnBoot(ctx context.Context, sb secureboot.State) error {
	if c.key == nil {
		return codes.New(codes.KeyCustodyLocked, "the state isn't unlocked")
	}
	h := c.header
	enforcing := sb.Supported && sb.Enforcing && sb.OrgOnly
	switch {
	case h.SecureBoot == SBOn && enforcing:
		if h.Mode == ModeTPM {
			if !c.hasCopy(ctx, PCRs7And11) {
				if err := c.sealCurrent(ctx, PCRs7And11); err != nil {
					return err
				}
			}
			if err := c.checkUnseals(ctx, PCRs7And11); err != nil {
				return err
			}
			if err := c.dropCopies(ctx, PCRs4And11); err != nil {
				return err
			}
		}
		if h.EnrolPending {
			h.EnrolPending = false
			if err := writeHeader(ctx, c.state, h); err != nil {
				return err
			}
			c.header = h
		}
	case h.SecureBoot == SBOff && !sb.Enforcing && h.Mode == ModeTPM:
		if c.hasCopy(ctx, PCRs4And11) {
			return c.dropCopies(ctx, PCRs7And11)
		}
	}
	return nil
}

// sealCurrent seals the key to the current values of pcrs.
func (c *Custody) sealCurrent(ctx context.Context, pcrs []int) error {
	if c.d.TPM == nil {
		return codes.New(codes.KeyCustodyNoTPM, "TPM custody without a TPM")
	}
	return addTPMCopy(ctx, c.d.TPM, c.state, c.key, pcrs, "")
}

func (c *Custody) copiesFor(ctx context.Context, pcrs []int) ([]tpmCopy, error) {
	all, err := tpmCopies(ctx, c.state)
	if err != nil {
		return nil, err
	}
	var out []tpmCopy
	for _, cp := range all {
		if slices.Equal(cp.tok.PCRs, pcrs) {
			out = append(out, cp)
		}
	}
	return out, nil
}

func (c *Custody) hasCopy(ctx context.Context, pcrs []int) bool {
	cps, err := c.copiesFor(ctx, pcrs)
	return err == nil && len(cps) > 0
}

func (c *Custody) checkUnseals(ctx context.Context, pcrs []int) error {
	cps, err := c.copiesFor(ctx, pcrs)
	if err != nil {
		return err
	}
	for _, cp := range cps {
		if k, err := cp.unseal(c.d.TPM); err == nil && bytes.Equal(k, c.key) {
			return nil
		}
	}
	return fmt.Errorf("keycustody: the new PCR %v copy doesn't unseal; keeping the old copies", pcrs)
}

func (c *Custody) dropCopies(ctx context.Context, pcrs []int) error {
	cps, err := c.copiesFor(ctx, pcrs)
	if err != nil {
		return err
	}
	for _, cp := range cps {
		if err := c.state.RemoveToken(ctx, cp.id); err != nil {
			return err
		}
	}
	return nil
}
