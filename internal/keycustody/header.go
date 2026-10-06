// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package keycustody

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/luks"
)

// HeaderTokenType is the LUKS2 token that records the custody mode and the
// Secure Boot choice on the state volume.
const HeaderTokenType = "sneakers-custody"

// Header is what the LUKS2 header records.
type Header struct {
	Mode       Mode `json:"mode"`
	SecureBoot SB   `json:"secureBoot"`
	// EnrolPending: Secure Boot was turned on later and the org keys
	// haven't been seen enforcing yet.
	EnrolPending bool `json:"enrolPending,omitempty"`
}

type headerToken struct {
	Type     string   `json:"type"`
	Keyslots []string `json:"keyslots"`
	Header
}

func readHeader(ctx context.Context, v Volume) (Header, error) {
	toks, err := v.Tokens(ctx)
	if err != nil {
		return Header{}, codes.Wrap(codes.KeyCustodyNotInitialized, err)
	}
	for _, raw := range toks {
		var t headerToken
		if json.Unmarshal(raw, &t) == nil && t.Type == HeaderTokenType {
			if t.Mode != ModeTPM && t.Mode != ModeKeyfile {
				return Header{}, codes.New(codes.KeyCustodyNotInitialized, "the header records custody mode %q", t.Mode)
			}
			return t.Header, nil
		}
	}
	return Header{}, codes.New(codes.KeyCustodyNotInitialized, "the state volume has no custody header")
}

// writeHeader replaces the header token.
func writeHeader(ctx context.Context, v Volume, h Header) error {
	toks, err := v.Tokens(ctx)
	if err != nil {
		return err
	}
	for id, raw := range toks {
		var t headerToken
		if json.Unmarshal(raw, &t) == nil && t.Type == HeaderTokenType {
			if err := v.RemoveToken(ctx, id); err != nil {
				return err
			}
			delete(toks, id)
		}
	}
	b, err := json.Marshal(headerToken{Type: HeaderTokenType, Keyslots: []string{}, Header: h})
	if err != nil {
		return err
	}
	return v.ImportToken(ctx, freeID(toks), b)
}

func freeID(toks map[int][]byte) int {
	for id := 0; ; id++ {
		if _, used := toks[id]; !used {
			return id
		}
	}
}

// tpmCopy is one sealed copy of the state key.
type tpmCopy struct {
	id  int
	tok *luks.TPM2Token
}

func (c tpmCopy) unseal(s Sealer) ([]byte, error) {
	priv, pub, err := c.tok.SealedBlobs()
	if err != nil {
		return nil, err
	}
	return s.UnsealWithPCR(priv, pub, c.tok.PCRs)
}

func tpmCopies(ctx context.Context, v Volume) ([]tpmCopy, error) {
	toks, err := v.Tokens(ctx)
	if err != nil {
		return nil, codes.Wrap(codes.KeyCustodyLocked, err)
	}
	var out []tpmCopy
	for id, raw := range toks {
		t, err := luks.ParseTPM2Token(raw)
		if err == nil {
			out = append(out, tpmCopy{id: id, tok: t})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out, nil
}

// addTPMCopy seals key to pcrs and stores it as a new token.
func addTPMCopy(ctx context.Context, s Sealer, v Volume, key []byte, pcrs []int, imageSHA string) error {
	priv, pub, err := s.SealToPCR(key, pcrs)
	if err != nil {
		return fmt.Errorf("keycustody: seal to PCR %v: %w", pcrs, err)
	}
	tok, err := luks.BuildTPM2Token(priv, pub, 0, pcrs, nil)
	if err != nil {
		return err
	}
	tok.ImageSHA256 = imageSHA
	b, err := tok.MarshalJSON()
	if err != nil {
		return err
	}
	toks, err := v.Tokens(ctx)
	if err != nil {
		return err
	}
	return v.ImportToken(ctx, freeID(toks), b)
}
