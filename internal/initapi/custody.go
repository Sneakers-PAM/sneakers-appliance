// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package initapi

import (
	"context"
	"errors"
	"sync"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/secureboot"
)

// custodyHandler serves KeyCustodyService over the custody init unlocked
// at boot. Initialize and SetSecureBoot stay Unimplemented: init fixes the
// custody at its own first-boot protection step.
type custodyHandler struct {
	initv1connect.UnimplementedKeyCustodyServiceHandler
	// mu serializes the custody: Seal writes files, Escrow reads them.
	mu  sync.Mutex
	c   *keycustody.Custody
	sb  secureboot.State
	log log.Logger
}

func (h *custodyHandler) Mode(context.Context, *connect.Request[initv1.ModeRequest]) (*connect.Response[initv1.ModeResponse], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return connect.NewResponse(&initv1.ModeResponse{Mode: modeProto(h.c.Mode())}), nil
}

func (h *custodyHandler) Protection(context.Context, *connect.Request[initv1.ProtectionRequest]) (*connect.Response[initv1.ProtectionResponse], error) {
	h.mu.Lock()
	hdr := h.c.Header()
	h.mu.Unlock()
	p := keycustody.ProtectionFor(h.sb, hdr.SecureBoot, hdr.Mode)
	level := initv1.ProtectionLevel_PROTECTION_LEVEL_FULL
	if p.Level == keycustody.LevelReduced {
		level = initv1.ProtectionLevel_PROTECTION_LEVEL_REDUCED
	}
	return connect.NewResponse(&initv1.ProtectionResponse{Level: level, Reason: string(p.Reason)}), nil
}

func (h *custodyHandler) Seal(_ context.Context, r *connect.Request[initv1.SealRequest]) (*connect.Response[initv1.SealResponse], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.c.Seal(r.Msg.GetName(), r.Msg.GetSecret()); err != nil {
		h.log.Warn("initapi: KeyCustody.Seal refused", log.F("item", r.Msg.GetName()), log.F("error", codes.Describe(err)))
		return nil, custodyError(err)
	}
	h.log.Info("initapi: KeyCustody.Seal", log.F("item", r.Msg.GetName()))
	return connect.NewResponse(&initv1.SealResponse{}), nil
}

func (h *custodyHandler) Unseal(_ context.Context, r *connect.Request[initv1.UnsealRequest]) (*connect.Response[initv1.UnsealResponse], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	secret, err := h.c.Unseal(r.Msg.GetName())
	if err != nil {
		h.log.Debug("initapi: KeyCustody.Unseal", log.F("item", r.Msg.GetName()), log.F("error", codes.Describe(err)))
		return nil, custodyError(err)
	}
	h.log.Debug("initapi: KeyCustody.Unseal", log.F("item", r.Msg.GetName()))
	return connect.NewResponse(&initv1.UnsealResponse{Secret: secret}), nil
}

func (h *custodyHandler) Escrow(_ context.Context, r *connect.Request[initv1.EscrowRequest]) (*connect.Response[initv1.EscrowResponse], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	b, err := h.c.Escrow(r.Msg.GetRecipients())
	if err != nil {
		h.log.Warn("initapi: KeyCustody.Escrow refused", log.F("error", codes.Describe(err)))
		return nil, custodyError(err)
	}
	h.log.Info("initapi: KeyCustody.Escrow", log.F("recipients", len(r.Msg.GetRecipients())))
	return connect.NewResponse(&initv1.EscrowResponse{Bundle: b}), nil
}

func modeProto(m keycustody.Mode) initv1.CustodyMode {
	switch m {
	case keycustody.ModeTPM:
		return initv1.CustodyMode_CUSTODY_MODE_TPM
	case keycustody.ModeKeyfile:
		return initv1.CustodyMode_CUSTODY_MODE_KEYFILE
	}
	return initv1.CustodyMode_CUSTODY_MODE_UNSPECIFIED
}

// custodyError maps a custody code to a Connect error whose message starts
// with the code's symbol.
func custodyError(err error) error {
	code, ok := codes.Of(err)
	if !ok {
		return connect.NewError(connect.CodeInternal, err)
	}
	c := connect.CodeFailedPrecondition
	switch code {
	case codes.KeyCustodyNotFound:
		c = connect.CodeNotFound
	case codes.KeyCustodyInvalid, codes.KeyCustodyRecipients:
		c = connect.CodeInvalidArgument
	}
	return connect.NewError(c, errors.New(codes.Describe(err)))
}
