// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package keycustody

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"sort"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/phase"
)

// Imported says what an ImportEscrow did, by item name; never a value.
type Imported struct {
	// Imported are the escrow's items that were sealed here.
	Imported []string
	// Kept are the escrow's items this box had already sealed for itself,
	// which stay as they are: the box's own SSH root key, pepper and host
	// CA, made when it first started, are never replaced by the old box's.
	Kept []string
}

// ImportEscrow restores the sealed items of another box onto this one, for
// a restore onto new hardware. plaintext is an escrow bundle already
// decrypted with a recovery key. It runs only in firstboot. Each item the
// escrow holds that isn't sealed here yet is sealed again under this box's
// own state key, which is never replaced by the old box's key; an item that
// is already sealed here is kept and never overwritten. An escrow that
// brings nothing new is refused.
func (c *Custody) ImportEscrow(plaintext []byte) (Imported, error) {
	var res Imported
	if c.d.Phase == nil || c.d.Phase() != phase.Firstboot {
		return res, codes.New(codes.KeyCustodyPhase, "an escrow is imported only in firstboot")
	}
	existing, err := c.sealedNames()
	if err != nil {
		return res, err
	}
	var e EscrowContents
	if err := json.Unmarshal(plaintext, &e); err != nil {
		return res, codes.New(codes.KeyCustodyInvalid, "the escrow doesn't parse: %v", err)
	}
	if e.Version != 1 {
		return res, codes.New(codes.KeyCustodyInvalid, "escrow version %d isn't supported", e.Version)
	}
	names := make([]string, 0, len(e.Items))
	for n := range e.Items {
		if !itemNameRE.MatchString(n) {
			return res, codes.New(codes.KeyCustodyInvalid, "sealed item name %q", n)
		}
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if slices.Contains(existing, n) {
			res.Kept = append(res.Kept, n)
			continue
		}
		res.Imported = append(res.Imported, n)
	}
	if len(res.Imported) == 0 {
		return Imported{}, codes.New(codes.KeyCustodyPhase, "the escrow brings nothing this box hasn't already sealed")
	}
	for _, n := range res.Imported {
		if err := c.Seal(n, e.Items[n]); err != nil {
			return Imported{}, err
		}
	}
	return res, nil
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
