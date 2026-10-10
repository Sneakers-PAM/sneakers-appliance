// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/types/known/timestamppb"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
)

const protectionNoticeFile = "protection-notice.json"

// protectionAck is an admin's acknowledgement of the reduced-protection
// notice, for one level and reason. It's kept on the state volume, so it
// holds across reboots and updates, until protection changes.
type protectionAck struct {
	Level  string    `json:"level"`
	Reason string    `json:"reason"`
	By     string    `json:"by"`
	At     time.Time `json:"at"`
}

func (s *Server) protectionAck() *protectionAck {
	b, err := os.ReadFile(s.ownPath(protectionNoticeFile)) // #nosec G304 -- osadmin's own file
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.o.Logger.Warn("osadmin: the protection notice acknowledgement is unreadable", log.F("error", err.Error()))
		}
		return nil
	}
	var a protectionAck
	if err := json.Unmarshal(b, &a); err != nil {
		s.o.Logger.Warn("osadmin: the protection notice acknowledgement is malformed", log.F("error", err.Error()))
		return nil
	}
	return &a
}

// protectionNotice is the acknowledgement for the box's reduced level and
// reason now, or nil when there's none for them.
func (s *Server) protectionNotice(reason string) *osadminv1.ProtectionNotice {
	a := s.protectionAck()
	if a == nil || a.Level != "reduced" || a.Reason != reason {
		return nil
	}
	return &osadminv1.ProtectionNotice{Hidden: true, HiddenBy: a.By, HiddenAt: timestamppb.New(a.At)}
}

// clearProtectionAck drops the acknowledgement once protection is full,
// so a later drop shows the notice again.
func (s *Server) clearProtectionAck() {
	err := os.Remove(s.ownPath(protectionNoticeFile))
	switch {
	case err == nil:
		s.o.Logger.Info("osadmin: protection is full; the hidden protection notice is cleared")
	case !errors.Is(err, fs.ErrNotExist):
		s.o.Logger.Warn("osadmin: the protection notice acknowledgement wasn't cleared", log.F("error", err.Error()))
	}
}

func (h *status) HideProtectionNotice(ctx context.Context, r *connect.Request[osadminv1.HideProtectionNoticeRequest]) (*connect.Response[osadminv1.HideProtectionNoticeResponse], error) {
	s, c := h.s, callFrom(ctx)
	want := r.Msg.GetReason()
	c.note("protection notice", "level", "reduced", "reason", want)
	prot, err := s.o.KeyCustody.Protection(ctx, connect.NewRequest(&initv1.ProtectionRequest{}))
	if err != nil {
		return nil, err
	}
	if prot.Msg.GetLevel() != initv1.ProtectionLevel_PROTECTION_LEVEL_REDUCED || prot.Msg.GetReason() != want {
		now := "full"
		if prot.Msg.GetLevel() == initv1.ProtectionLevel_PROTECTION_LEVEL_REDUCED {
			now = "reduced " + prot.Msg.GetReason()
		}
		c.note("protection notice", "hidden", "no", "now", now)
		s.o.Logger.Info("osadmin: protection notice not hidden: the box's protection isn't what the notice showed", log.F("asked", want), log.F("level", prot.Msg.GetLevel().String()), log.F("reason", prot.Msg.GetReason()), log.F("by", c.session.Admin))
		return connect.NewResponse(&osadminv1.HideProtectionNoticeResponse{}), nil
	}
	b, err := json.Marshal(protectionAck{Level: "reduced", Reason: want, By: c.session.Admin, At: s.o.Clock.Now().UTC()})
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(s.o.Paths.APIDir(), 0o700); err != nil {
		return nil, err
	}
	if err := writeAtomic(s.ownPath(protectionNoticeFile), b); err != nil {
		s.o.Logger.Error(err, "osadmin: the protection notice acknowledgement wasn't saved")
		return nil, err
	}
	s.o.Logger.Info("osadmin: protection notice hidden", log.F("reason", want), log.F("by", c.session.Admin))
	return connect.NewResponse(&osadminv1.HideProtectionNoticeResponse{Hidden: true}), nil
}
