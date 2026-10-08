// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/types/known/timestamppb"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

type audit struct {
	osadminv1connect.UnimplementedAuditServiceHandler
	s *Server
}

func (h *audit) ListEvents(_ context.Context, r *connect.Request[osadminv1.ListEventsRequest]) (*connect.Response[osadminv1.ListEventsResponse], error) {
	limit := int(r.Msg.GetLimit())
	if limit <= 0 {
		limit = 100
	}
	limit = min(limit, 500)
	skip := 0
	if t := r.Msg.GetPageToken(); t != "" {
		n, err := strconv.Atoi(t)
		if err != nil || n < 0 {
			return nil, codes.New(codes.AccessForbidden, "the page token isn't one this box issued")
		}
		skip = n
	}
	out := &osadminv1.ListEventsResponse{ChainOk: true}
	if err := h.s.o.Audit.Verify(); err != nil {
		out.ChainOk, out.ChainError = false, err.Error()
	}
	all, err := h.s.o.Audit.Entries()
	if err != nil {
		return nil, err
	}
	slices.Reverse(all)
	var match []osaudit.Entry
	for _, e := range all {
		if strings.HasPrefix(e.Action, r.Msg.GetAction()) {
			match = append(match, e)
		}
	}
	for i := skip; i < len(match) && i < skip+limit; i++ {
		e := match[i]
		out.Events = append(out.Events, &osadminv1.AuditEvent{
			Time: timestamppb.New(e.Time), Actor: e.Actor, KeyFingerprint: e.KeyFP, SourceAddress: e.Source,
			Action: e.Action, Target: e.Target, Outcome: e.Outcome, Code: e.Code, Detail: e.Detail,
		})
	}
	if skip+limit < len(match) {
		out.NextPageToken = strconv.Itoa(skip + limit)
	}
	return connect.NewResponse(out), nil
}

// exportAudit streams every day file, oldest first, as JSON lines: the log
// as written, so the chain verifies off the box too.
func (s *Server) exportAudit(w http.ResponseWriter, r *http.Request) {
	sess, err := s.session(r.Header)
	if err == nil {
		_, err = s.liveRole(sess)
	}
	entry := osaudit.Entry{Actor: sess.Admin, Source: hostOf(r.RemoteAddr), Action: "audit.export"}
	if err != nil {
		s.write(entry, err)
		http.Error(w, codes.Describe(err), http.StatusUnauthorized)
		return
	}
	paths, _ := filepath.Glob(filepath.Join(s.o.Audit.Dir(), "log-*.jsonl"))
	slices.Sort(paths)
	w.Header().Set("Content-Type", "application/jsonl")
	w.Header().Set("Content-Disposition", `attachment; filename="os-audit.jsonl"`)
	s.write(entry, nil)
	for _, p := range paths {
		f, err := os.Open(p) // #nosec G304 -- a day file listed from the log directory
		if err != nil {
			s.o.Logger.Error(err, "osadmin: audit export: a day file can't be read", log.F("file", filepath.Base(p)))
			return
		}
		_, err = io.Copy(w, f)
		_ = f.Close()
		if err != nil {
			s.o.Logger.Warn("osadmin: audit export interrupted", log.F("error", err.Error()))
			return
		}
	}
	s.o.Logger.Info("osadmin: audit log exported", log.F("admin", sess.Admin), log.F("files", len(paths)))
}
