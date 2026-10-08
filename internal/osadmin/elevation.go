// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevation"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

// elevationSvc is the root shells' history, ending a live one, and the
// recordings. The rules live in package elevation; the role, step-up and
// audit entry come from each method's Rule.
type elevationSvc struct {
	osadminv1connect.UnimplementedElevationServiceHandler
	s *Server
}

// ElevationToWire is a root shell as the pages and the shell show it.
func ElevationToWire(r elevation.Request, auditDir string) *osadminv1.Elevation {
	ts := func(t *time.Time) *timestamppb.Timestamp {
		if t == nil {
			return nil
		}
		return timestamppb.New(*t)
	}
	e := &osadminv1.Elevation{
		Id: r.ID, Admin: r.Admin, KeyFingerprint: r.KeyFP, SourceAddress: r.Source, Reason: r.Reason,
		Minutes: int32(min(r.Minutes, 1<<30)), Requested: timestamppb.New(r.Requested), State: string(r.State), // #nosec G115 -- clamped
		ApprovedBy: r.ApprovedBy, Approved: ts(r.Approved), Started: ts(r.Started),
		Ended: ts(r.Ended), EndReason: r.EndReason, RecordingSha256: r.RecordingSHA256, ValidBefore: ts(r.ValidBefore),
	}
	if auditDir != "" && r.Started != nil {
		if _, err := os.Stat(osaudit.RecordingPath(auditDir, r.ID)); err == nil {
			e.Recording = true
		}
	}
	return e
}

func (h *elevationSvc) svc() (*elevation.Service, error) {
	if h.s.o.Elevation == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New(NotAvailable)) //nolint:staticcheck // shown to people as a sentence
	}
	return h.s.o.Elevation, nil
}

func (h *elevationSvc) auditDir() string {
	if h.s.o.Audit == nil {
		return ""
	}
	return h.s.o.Audit.Dir()
}

func (h *elevationSvc) ListElevations(_ context.Context, _ *connect.Request[osadminv1.ListElevationsRequest]) (*connect.Response[osadminv1.ListElevationsResponse], error) {
	svc, err := h.svc()
	if err != nil {
		return nil, err
	}
	out := &osadminv1.ListElevationsResponse{}
	for _, r := range svc.List() {
		out.Elevations = append(out.Elevations, ElevationToWire(r, h.auditDir()))
	}
	return connect.NewResponse(out), nil
}

func (h *elevationSvc) TerminateElevation(ctx context.Context, r *connect.Request[osadminv1.TerminateElevationRequest]) (*connect.Response[osadminv1.TerminateElevationResponse], error) {
	svc, err := h.svc()
	if err != nil {
		return nil, err
	}
	c := callFrom(ctx)
	c.noteID("root shell", "request", r.Msg.GetId())
	if cur, ok := svc.Get(r.Msg.GetId()); ok {
		c.noteID(cur.Name(), "request", cur.ID)
	}
	got, err := svc.Terminate(r.Msg.GetId(), c.session.Admin)
	if err != nil {
		return nil, err
	}
	c.noteID(got.Name(), "request", got.ID, "admin", got.Admin, "was", string(got.State))
	return connect.NewResponse(&osadminv1.TerminateElevationResponse{}), nil
}

// maxRecording bounds a recording sent in one response.
const maxRecording = 64 << 20

func (h *elevationSvc) GetElevationRecording(ctx context.Context, r *connect.Request[osadminv1.GetElevationRecordingRequest]) (*connect.Response[osadminv1.GetElevationRecordingResponse], error) {
	svc, err := h.svc()
	if err != nil {
		return nil, err
	}
	id := r.Msg.GetId()
	req, ok := svc.Get(id)
	callFrom(ctx).noteID(req.Name()+" recording", "request", id)
	if !ok || h.s.o.Audit == nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("there is no root shell "+id))
	}
	p := osaudit.RecordingPath(h.s.o.Audit.Dir(), id)
	fi, err := os.Stat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, connect.NewError(connect.CodeNotFound, errors.New(id+" left no recording"))
	}
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxRecording {
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("the recording is larger than 64 MiB; take it from a support bundle"))
	}
	data, err := os.ReadFile(p) // #nosec G304 -- the recording of a known request id
	if err != nil {
		return nil, err
	}
	out := &osadminv1.GetElevationRecordingResponse{Cast: data, Verified: true}
	if verr := osaudit.VerifyRecording(data, h.s.o.Audit, id); verr != nil {
		out.Verified, out.VerifyError = false, verr.Error()
	}
	return connect.NewResponse(out), nil
}
