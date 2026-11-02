// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"sync"
	"time"

	"connectrpc.com/connect" // scrub:allow=fqdn -- a Go module path
	log "github.com/Bugs5382/go-log"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/backupset"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// exportTicketLife is how long a ticket waits for its stream.
const exportTicketLife = time.Minute

// Backups is the box's backup sets (docs/backups.md).
type Backups struct {
	Sets    *backupset.Manager
	Restore *backupset.Restorer
	Guard   *backupset.Guard
}

// exportTickets are the exports an owner authorised and hasn't started. They
// live only here, so a restart forgets them.
type exportTickets struct {
	mu   sync.Mutex
	open map[string]exportTicket
}

type exportTicket struct {
	set, admin string
	until      time.Time
}

func (t *exportTickets) issue(set, admin string, now time.Time) (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.open == nil {
		t.open = map[string]exportTicket{}
	}
	for k, v := range t.open {
		if now.After(v.until) {
			delete(t.open, k)
		}
	}
	t.open[id] = exportTicket{set: set, admin: admin, until: now.Add(exportTicketLife)}
	return id, nil
}

// take uses a ticket up: it works once, for the admin it was issued to.
func (t *exportTickets) take(id, admin string, now time.Time) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.open[id]
	delete(t.open, id)
	if !ok || v.admin != admin || now.After(v.until) {
		return "", false
	}
	return v.set, true
}

func (s *Server) backups() (Backups, error) {
	if s.o.Backups == nil {
		return Backups{}, codes.New(codes.BackupSet, "this box doesn't keep backup sets")
	}
	return *s.o.Backups, nil
}

func setToWire(n, point string, taken time.Time, bytes int64) *osadminv1.BoxBackupSet {
	return &osadminv1.BoxBackupSet{Name: n, Point: point, Taken: taken.Format(time.RFC3339), Bytes: uint64(max(bytes, 0))} // #nosec G115 -- held at 0 or more
}

// ListBackups lists the sets.
func (h *productSvc) ListBackups(context.Context, *connect.Request[osadminv1.ListBackupsRequest]) (*connect.Response[osadminv1.ListBackupsResponse], error) {
	out := &osadminv1.ListBackupsResponse{}
	b, err := h.s.backups()
	if err != nil {
		return nil, err
	}
	list, err := b.Sets.List()
	if err != nil {
		return nil, err
	}
	for _, x := range list {
		out.Sets = append(out.Sets, setToWire(x.Name, x.Point, x.Taken, x.Bytes))
	}
	return connect.NewResponse(out), nil
}

// CreateBackup cuts a set while the product runs.
func (h *productSvc) CreateBackup(ctx context.Context, r *connect.Request[osadminv1.CreateBackupRequest]) (*connect.Response[osadminv1.CreateBackupResponse], error) {
	c := callFrom(ctx)
	b, err := h.s.backups()
	if err != nil {
		return nil, err
	}
	if b.Restore.Active() {
		return nil, codes.New(codes.BackupBusy, "a restore is under way")
	}
	mf, err := b.Sets.Create(ctx, r.Msg.GetName())
	c.note(mf.Name, "point", mf.Point)
	if err != nil {
		h.s.o.Logger.Warn("osadmin: a backup set wasn't made", log.F("by", c.session.Admin), log.F("error", err.Error()))
		return nil, err
	}
	return connect.NewResponse(&osadminv1.CreateBackupResponse{Set: setToWire(mf.Name, mf.Point, mf.Taken, mf.Bytes)}), nil
}

// RemoveBackup removes a set, for an owner who asked by name.
func (h *productSvc) RemoveBackup(ctx context.Context, r *connect.Request[osadminv1.RemoveBackupRequest]) (*connect.Response[osadminv1.RemoveBackupResponse], error) {
	c := callFrom(ctx)
	c.note(r.Msg.GetName())
	b, err := h.s.backups()
	if err != nil {
		return nil, err
	}
	if b.Restore.Active() {
		return nil, codes.New(codes.BackupBusy, "a restore is under way")
	}
	if err := b.Sets.Remove(r.Msg.GetName()); err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.RemoveBackupResponse{}), nil
}

// RestoreBackup starts a restore: the phase loop takes it from here, and
// Updates and the console follow it like any other step.
func (h *productSvc) RestoreBackup(ctx context.Context, r *connect.Request[osadminv1.RestoreBackupRequest]) (*connect.Response[osadminv1.RestoreBackupResponse], error) {
	c := callFrom(ctx)
	name := r.Msg.GetName()
	c.note(name)
	b, err := h.s.backups()
	if err != nil {
		return nil, err
	}
	if h.s.UpdateBusy() {
		return nil, codes.New(codes.BackupBusy, "an update is under way")
	}
	if m, ok := h.s.o.ProductUp.(moveFollower); ok && m.MoveUnsettled() {
		return nil, codes.New(codes.BackupBusy, "the box hasn't settled on its data move")
	}
	if err := b.Restore.Request(ctx, name, c.session.Admin); err != nil {
		h.s.o.Logger.Warn("osadmin: a restore was refused", log.F("set", name), log.F("by", c.session.Admin), log.F("error", err.Error()))
		return nil, err
	}
	h.s.startProductUp()
	return connect.NewResponse(&osadminv1.RestoreBackupResponse{}), nil
}

// PrepareBackupExport issues the one-time ticket for an export.
func (h *productSvc) PrepareBackupExport(ctx context.Context, r *connect.Request[osadminv1.PrepareBackupExportRequest]) (*connect.Response[osadminv1.PrepareBackupExportResponse], error) {
	c := callFrom(ctx)
	name := r.Msg.GetName()
	c.note(name)
	if err := backupset.CheckName(name); err != nil {
		return nil, err
	}
	id, err := h.s.exports.issue(name, c.session.Admin, time.Now())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.PrepareBackupExportResponse{Ticket: id}), nil
}

// WriteBackupExport writes the set a ticket names to w, for the closed shell.
func (s *Server) WriteBackupExport(ctx context.Context, w io.Writer, l Local, ticket string) error {
	set, ok := s.exports.take(ticket, l.Admin, time.Now())
	if !ok {
		return codes.New(codes.AccessForbidden, "that export ticket isn't good")
	}
	b, err := s.backups()
	if err != nil {
		return err
	}
	n, err := b.Sets.Export(ctx, set, w)
	s.o.Logger.Info("osadmin: a backup set was exported", log.F("set", set), log.F("by", l.Admin), log.F("bytes", n), log.F("ok", err == nil))
	return err
}
