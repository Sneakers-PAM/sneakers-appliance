// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"time"

	"connectrpc.com/connect" // scrub:allow=fqdn -- a Go module path
	log "github.com/Bugs5382/go-log"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/datamove"
)

// dumpKeeper is a probe that reaches the dumps a data move kept of what it
// replaced (docs/data-move.md).
type dumpKeeper interface {
	KeptDumps() ([]datamove.KeptDump, error)
	RemoveKeptDump(name string) error
}

// ListKeptDumps lists the kept dumps.
func (h *productSvc) ListKeptDumps(context.Context, *connect.Request[osadminv1.ListKeptDumpsRequest]) (*connect.Response[osadminv1.ListKeptDumpsResponse], error) {
	out := &osadminv1.ListKeptDumpsResponse{}
	k, ok := h.s.o.ProductUp.(dumpKeeper)
	if !ok {
		return connect.NewResponse(out), nil
	}
	list, err := k.KeptDumps()
	if err != nil {
		return nil, err
	}
	for _, d := range list {
		out.Dumps = append(out.Dumps, &osadminv1.KeptDump{Name: d.Name, Path: d.Path, Taken: d.At.Format(time.RFC3339), Bytes: uint64(max(d.Bytes, 0)), Whole: d.Whole}) // #nosec G115 -- held at 0 or more
	}
	return connect.NewResponse(out), nil
}

// RemoveKeptDump removes one kept dump, for an owner who asked by name; the
// rule writes the audit entry either way.
func (h *productSvc) RemoveKeptDump(ctx context.Context, r *connect.Request[osadminv1.RemoveKeptDumpRequest]) (*connect.Response[osadminv1.RemoveKeptDumpResponse], error) {
	c := callFrom(ctx)
	name := r.Msg.GetName()
	c.note(name)
	k, ok := h.s.o.ProductUp.(dumpKeeper)
	if !ok {
		return nil, codes.New(codes.DataMoveDump, "there's no kept dump %s", name)
	}
	if err := k.RemoveKeptDump(name); err != nil {
		h.s.o.Logger.Warn("osadmin: the kept dump wasn't removed", log.F("dump", name), log.F("by", c.session.Admin), log.F("error", err.Error()))
		return nil, err
	}
	h.s.o.Logger.Info("osadmin: a kept dump was removed", log.F("dump", name), log.F("by", c.session.Admin))
	return connect.NewResponse(&osadminv1.RemoveKeptDumpResponse{}), nil
}
