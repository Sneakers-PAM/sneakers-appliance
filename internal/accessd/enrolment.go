// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accounts"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/enrol"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/initapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
)

type enrolmentH struct {
	accessv1connect.UnimplementedEnrolmentServiceHandler
	s *Server
}

var errEnrolNotAvailable = connect.NewError(connect.CodeUnimplemented, errors.New(osadmin.NotAvailable)) //nolint:staticcheck // shown to people as a sentence

// console checks the caller is root: the window is opened, decided and
// closed on the console only.
func (h *enrolmentH) console(ctx context.Context, procedure string) (*enrol.Service, error) {
	p, ok := initapi.PeerFrom(ctx)
	if !ok || p.UID != 0 {
		h.s.o.Logger.Warn("accessd: an enrolment console call from a non-root peer; refused", log.F("procedure", procedure))
		return nil, refuse(codes.New(codes.AccessForbidden, "the enrolment window is run from the console"))
	}
	if h.s.o.Enrolment == nil {
		return nil, errEnrolNotAvailable
	}
	return h.s.o.Enrolment, nil
}

// session checks the caller is the enrol uid: sneakers-enrol.
func (h *enrolmentH) session(ctx context.Context, procedure string) (*enrol.Service, error) {
	p, ok := initapi.PeerFrom(ctx)
	if !ok || p.UID != accounts.EnrolUID {
		h.s.o.Logger.Warn("accessd: an enrol-session call from another peer; refused", log.F("procedure", procedure))
		return nil, refuse(codes.New(codes.AccessForbidden, "only the enrol account's session sends a code"))
	}
	if h.s.o.Enrolment == nil {
		return nil, errEnrolNotAvailable
	}
	return h.s.o.Enrolment, nil
}

func (h *enrolmentH) wire(v enrol.View) *accessv1.Enrolment {
	e := &accessv1.Enrolment{
		Open: v.Open, Admin: v.Admin, Code: v.Code, AttemptsLeft: int32(min(v.AttemptsLeft, 1<<30)), // #nosec G115 -- clamped
		Enrolled: int32(min(v.Enrolled, 1<<30)), ClosedReason: v.ClosedReason, // #nosec G115 -- clamped
		Recovery: v.Recovery,
	}
	if !v.Opened.IsZero() {
		e.Opened = timestamppb.New(v.Opened)
	}
	if !v.IdleUntil.IsZero() {
		e.IdleUntil = timestamppb.New(v.IdleUntil)
	}
	if h.s.api != nil {
		e.HostKeys = h.s.api.HostKeys()
	}
	for _, k := range v.Keys {
		e.Keys = append(e.Keys, keyToWire(k))
	}
	return e
}

func keyToWire(k enrol.Key) *accessv1.EnrolmentKey {
	return &accessv1.EnrolmentKey{Id: k.ID, Fingerprint: k.Fingerprint, Type: k.Type, Comment: k.Comment, SourceAddress: k.Source, State: string(k.State), Via: k.Via}
}

// OpenEnrolment opens the window, making the SSH host keys first if the
// box has none, so the console can show their fingerprints.
func (h *enrolmentH) OpenEnrolment(ctx context.Context, r *connect.Request[accessv1.OpenEnrolmentRequest]) (*connect.Response[accessv1.OpenEnrolmentResponse], error) {
	svc, err := h.console(ctx, accessv1connect.EnrolmentServiceOpenEnrolmentProcedure)
	if err != nil {
		return nil, err
	}
	if h.s.o.HostKeyDir != "" {
		if err := EnsureHostKeys(h.s.o.HostKeyDir); err != nil {
			h.s.o.Logger.Error(err, "accessd: SSH host keys not made")
			return nil, err
		}
	}
	v, err := svc.OpenWith(r.Msg.GetAdmin(), enrol.OpenOptions{Recovery: r.Msg.GetRecovery()})
	if err != nil {
		return nil, coded(err)
	}
	return connect.NewResponse(&accessv1.OpenEnrolmentResponse{Enrolment: h.wire(v)}), nil
}

// OfferEnrolmentKey takes a key typed or fetched on the console into the
// open window.
func (h *enrolmentH) OfferEnrolmentKey(ctx context.Context, r *connect.Request[accessv1.OfferEnrolmentKeyRequest]) (*connect.Response[accessv1.OfferEnrolmentKeyResponse], error) {
	svc, err := h.console(ctx, accessv1connect.EnrolmentServiceOfferEnrolmentKeyProcedure)
	if err != nil {
		return nil, err
	}
	via := r.Msg.GetVia()
	if via != access.ViaTyped && via != access.ViaURL {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("via is %s or %s", access.ViaTyped, access.ViaURL))
	}
	k, err := svc.Offer(r.Msg.GetPublicKey(), via, r.Msg.GetFrom())
	if err != nil {
		return nil, coded(err)
	}
	return connect.NewResponse(&accessv1.OfferEnrolmentKeyResponse{Key: keyToWire(k)}), nil
}

func (h *enrolmentH) GetEnrolment(ctx context.Context, _ *connect.Request[accessv1.GetEnrolmentRequest]) (*connect.Response[accessv1.GetEnrolmentResponse], error) {
	svc, err := h.console(ctx, accessv1connect.EnrolmentServiceGetEnrolmentProcedure)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.GetEnrolmentResponse{Enrolment: h.wire(svc.Get())}), nil
}

func (h *enrolmentH) AcceptEnrolmentKey(ctx context.Context, r *connect.Request[accessv1.AcceptEnrolmentKeyRequest]) (*connect.Response[accessv1.AcceptEnrolmentKeyResponse], error) {
	svc, err := h.console(ctx, accessv1connect.EnrolmentServiceAcceptEnrolmentKeyProcedure)
	if err != nil {
		return nil, err
	}
	k, err := svc.Accept(r.Msg.GetId(), r.Msg.GetConfirm())
	if err != nil {
		return nil, coded(err)
	}
	return connect.NewResponse(&accessv1.AcceptEnrolmentKeyResponse{Key: &osadminv1.Key{Fingerprint: k.Fingerprint, Type: k.Type, Comment: k.Comment}}), nil
}

func (h *enrolmentH) RejectEnrolmentKey(ctx context.Context, r *connect.Request[accessv1.RejectEnrolmentKeyRequest]) (*connect.Response[accessv1.RejectEnrolmentKeyResponse], error) {
	svc, err := h.console(ctx, accessv1connect.EnrolmentServiceRejectEnrolmentKeyProcedure)
	if err != nil {
		return nil, err
	}
	if err := svc.Reject(r.Msg.GetId()); err != nil {
		return nil, coded(err)
	}
	return connect.NewResponse(&accessv1.RejectEnrolmentKeyResponse{}), nil
}

func (h *enrolmentH) CloseEnrolment(ctx context.Context, _ *connect.Request[accessv1.CloseEnrolmentRequest]) (*connect.Response[accessv1.CloseEnrolmentResponse], error) {
	svc, err := h.console(ctx, accessv1connect.EnrolmentServiceCloseEnrolmentProcedure)
	if err != nil {
		return nil, err
	}
	svc.Close(enrol.ReasonDone)
	return connect.NewResponse(&accessv1.CloseEnrolmentResponse{}), nil
}

func (h *enrolmentH) SubmitEnrolmentCode(ctx context.Context, r *connect.Request[accessv1.SubmitEnrolmentCodeRequest]) (*connect.Response[accessv1.SubmitEnrolmentCodeResponse], error) {
	svc, err := h.session(ctx, accessv1connect.EnrolmentServiceSubmitEnrolmentCodeProcedure)
	if err != nil {
		return nil, err
	}
	k, err := svc.Submit(r.Msg.GetCode(), r.Msg.GetPublicKey(), r.Header().Get(accessapi.SourceHeader))
	if err != nil {
		return nil, coded(err)
	}
	return connect.NewResponse(&accessv1.SubmitEnrolmentCodeResponse{Id: k.ID, Admin: svc.Get().Admin, Fingerprint: k.Fingerprint}), nil
}

func (h *enrolmentH) GetEnrolmentKey(ctx context.Context, r *connect.Request[accessv1.GetEnrolmentKeyRequest]) (*connect.Response[accessv1.GetEnrolmentKeyResponse], error) {
	svc, err := h.session(ctx, accessv1connect.EnrolmentServiceGetEnrolmentKeyProcedure)
	if err != nil {
		return nil, err
	}
	k, err := svc.Key(r.Msg.GetId())
	if err != nil {
		return nil, coded(err)
	}
	return connect.NewResponse(&accessv1.GetEnrolmentKeyResponse{Key: keyToWire(k)}), nil
}

// EnsureHostKeys makes the SSH host keys (ed25519 and RSA-3072) in dir
// when they are missing: first-boot step 3 does this before it shows the
// fingerprints.
func EnsureHostKeys(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, kind := range []string{"ed25519", "rsa"} {
		p := filepath.Join(dir, "ssh_host_"+kind+"_key")
		if _, err := os.Stat(p); err == nil {
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		var priv any
		if kind == "ed25519" {
			_, k, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			priv = k
		} else {
			k, err := rsa.GenerateKey(rand.Reader, 3072)
			if err != nil {
				return err
			}
			priv = k
		}
		block, err := ssh.MarshalPrivateKey(priv, "")
		if err != nil {
			return err
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			return err
		}
		if err := os.WriteFile(p+".tmp", pem.EncodeToMemory(block), 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(p+".pub", ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o644); err != nil { // #nosec G306 -- a public key
			return err
		}
		if err := os.Rename(p+".tmp", p); err != nil {
			return fmt.Errorf("host key %s: %w", kind, err)
		}
	}
	return nil
}
