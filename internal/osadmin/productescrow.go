// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"bytes"
	"context"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// productEscrowName is a product key's sealed item: "product-<product>-<name>".
func productEscrowName(product, name string) string { return "product-" + product + "-" + name }

// sealProductKeys seals each key the installed product's product.yaml names
// for the escrow under KeyCustody, so the recovery escrow carries it. It
// reports whether any sealed item changed. A key the box can't read yet (the
// product hasn't made it) is left for the next time.
func (s *Server) sealProductKeys(ctx context.Context) (bool, error) {
	info, spec := s.installedSpec()
	if !info.Present() || len(spec.Escrow) == 0 || s.o.Exposed == nil {
		return false, nil
	}
	changed := false
	for _, e := range spec.Escrow {
		val, err := s.o.Exposed.SecretKey(ctx, e.Namespace(), e.SecretName(), e.Key)
		if err != nil {
			s.o.Logger.Warn("osadmin: a product key for the escrow can't be read yet; it's sealed next time", log.F("key", e.Name), log.F("error", err.Error()))
			continue
		}
		name := productEscrowName(info.Name, e.Name)
		if cur, err := s.o.KeyCustody.Unseal(ctx, connect.NewRequest(&initv1.UnsealRequest{Name: name})); err == nil && bytes.Equal(cur.Msg.GetSecret(), []byte(val)) {
			continue
		}
		if _, err := s.o.KeyCustody.Seal(ctx, connect.NewRequest(&initv1.SealRequest{Name: name, Secret: []byte(val)})); err != nil {
			return changed, err
		}
		changed = true
		s.o.Logger.Info("osadmin: a product key is sealed for the escrow", log.F("key", e.Name), log.F("product", info.Name))
	}
	return changed, nil
}

// refreshEscrow seals the product's keys and, when one changed, writes a
// new escrow file to the current recovery keys.
func (s *Server) refreshEscrow(ctx context.Context) error {
	changed, err := s.sealProductKeys(ctx)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	if len(s.o.Access.Read().RecoveryKeys) == 0 {
		return codes.New(codes.SetupIncomplete, "there is no recovery key yet; add one first")
	}
	return s.changeRecoveryKeys(ctx, func(*access.State) error { return nil })
}
