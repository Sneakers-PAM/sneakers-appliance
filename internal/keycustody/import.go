// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package keycustody

import (
	"encoding/json"
	"errors"
	"os"
	"sort"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/phase"
)

// ImportEscrow restores the sealed items of another box onto this one, for
// a restore onto new hardware. plaintext is an escrow bundle already
// decrypted with a recovery key. It runs only in firstboot and only before
// any sealed item exists here; each item is sealed again under this box's
// own state key, which is never replaced by the old box's key.
func (c *Custody) ImportEscrow(plaintext []byte) error {
	if c.d.Phase == nil || c.d.Phase() != phase.Firstboot {
		return codes.New(codes.KeyCustodyPhase, "an escrow is imported only in firstboot")
	}
	existing, err := c.sealedNames()
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		return codes.New(codes.KeyCustodyPhase, "root secrets are already sealed on this box")
	}
	var e EscrowContents
	if err := json.Unmarshal(plaintext, &e); err != nil {
		return codes.New(codes.KeyCustodyInvalid, "the escrow doesn't parse: %v", err)
	}
	if e.Version != 1 {
		return codes.New(codes.KeyCustodyInvalid, "escrow version %d isn't supported", e.Version)
	}
	names := make([]string, 0, len(e.Items))
	for n := range e.Items {
		if !itemNameRE.MatchString(n) {
			return codes.New(codes.KeyCustodyInvalid, "sealed item name %q", n)
		}
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := c.Seal(n, e.Items[n]); err != nil {
			return err
		}
	}
	return nil
}

func (c *Custody) sealedNames() ([]string, error) {
	entries, err := os.ReadDir(c.sealedDir())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if itemNameRE.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}
