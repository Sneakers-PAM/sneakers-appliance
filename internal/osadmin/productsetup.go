// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productinfo"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productsetup"
)

func (s *Server) productSetup() *productsetup.Store {
	return productsetup.New(s.o.Paths.ProductSetupDir())
}

// ensureProductSetupToken makes the product's setup token once the box's
// first admin exists, before any product starts (k0s waits for setup to
// finish), so the product's Secret has it from its first start.
func (s *Server) ensureProductSetupToken() {
	if err := s.productSetup().Ensure(); err != nil {
		s.o.Logger.Error(err, "osadmin: the product setup token wasn't made")
		return
	}
	s.o.Logger.Debug("osadmin: the product setup token is in place")
}

// GetProductSetupToken gives the installed product's setup token while the
// product has no first admin, and consumes it once the product says it
// has one.
func (h *upgradeSvc) GetProductSetupToken(ctx context.Context, _ *connect.Request[osadminv1.GetProductSetupTokenRequest]) (*connect.Response[osadminv1.GetProductSetupTokenResponse], error) {
	s := h.s
	c := callFrom(ctx)
	st := s.productSetup()
	out := &osadminv1.GetProductSetupTokenResponse{Product: productinfo.Installed(s.slots().Dir).Title}
	if host := s.boxHost(ctx); host != "" {
		out.SetupUrl = "https://" + host + "/admin/setup"
	}
	if st.Consumed() {
		out.SetUp = true
		c.note("product", "state", "set-up")
		return connect.NewResponse(out), nil
	}
	if out.GetProduct() == "" {
		c.note("product", "state", "no-product")
		return connect.NewResponse(out), nil
	}
	if s.o.ProductNeedsSetup != nil {
		needs, err := s.o.ProductNeedsSetup(ctx)
		switch {
		case err != nil:
			s.o.Logger.Info("osadmin: the product's setup state isn't known yet; the token is kept", log.F("error", err.Error()))
		case !needs:
			if err := st.Consume(); err != nil {
				return nil, err
			}
			s.o.Logger.Info("osadmin: the product's first admin exists; the setup token is consumed and removed")
			out.SetUp = true
			c.note("product", "state", "set-up", "consumed", "now")
			return connect.NewResponse(out), nil
		}
	}
	if err := st.Ensure(); err != nil {
		return nil, err
	}
	out.Token, _ = st.Token()
	c.note("product", "state", "not-set-up")
	return connect.NewResponse(out), nil
}
