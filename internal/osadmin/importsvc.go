// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productimport"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productinfo"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// importDir is the import directory on the state volume; the import Job
// mounts it.
const importDir = "import"

type importSvc struct {
	osadminv1connect.UnimplementedImportServiceHandler
	s *Server
}

// importedMarker is where the box records that its product data came
// from an import: the imported-users mode.
func (s *Server) importedMarker() string {
	return filepath.Join(s.o.Paths.State, "platform", "imported.json")
}

// Imported reports whether the product's data came from an import.
func (s *Server) Imported() (productimport.Marker, bool) {
	return productimport.ReadMarker(s.importedMarker())
}

// importer is the installed product's import, or a reason there is none.
func (s *Server) importer() (*productimport.Manager, productinfo.Info, productspec.Spec, error) {
	info, spec := s.installedSpec()
	if !info.Present() {
		return nil, info, spec, codes.New(codes.NotAvailable, "no product is installed; install it from Updates first")
	}
	stack, ok := spec.ImportStack()
	if !ok || s.o.Switches == nil {
		return nil, info, spec, codes.New(codes.NotAvailable, "%s takes no import", info.Title)
	}
	return &productimport.Manager{
		Dir: filepath.Join(s.o.Paths.State, importDir), UID: spec.Import.UID,
		Stack: filepath.Join(s.o.Switches.Manifests, stack), Template: filepath.Join(s.o.Switches.Slot, spec.Import.Job),
		Clock: s.o.Clock, Logger: s.o.Logger, Chown: s.o.ImportChown,
	}, info, spec, nil
}

// setupDone reports whether the product's own first-run setup is done: its
// setup value is consumed, or its signal says so.
func (s *Server) setupDone(ctx context.Context, info productinfo.Info, spec productspec.Spec) bool {
	v, ok := spec.Find(spec.Import.Setup)
	if !ok {
		return false
	}
	if _, err := os.Stat(s.consumedMarker(info.Name, v.Name)); err == nil {
		return true
	}
	if s.o.Exposed == nil || v.ConsumedWhen == nil {
		return false
	}
	held, err := s.signalHolds(ctx, v)
	if err != nil {
		s.o.Logger.Info("osadmin: the product's setup signal isn't known yet; an import may open", log.F("error", err.Error()))
		return false
	}
	return held
}

func runToWire(r productimport.Run) *osadminv1.ImportRun {
	st := "running"
	switch {
	case r.Done && r.Exit == 0:
		st = "passed"
	case r.Done:
		st = "failed"
	}
	out := &osadminv1.ImportRun{Job: r.Job, Step: string(r.Step), State: st, ExitCode: int32(min(max(r.Exit, 0), 255)), // #nosec G115 -- clamped
		StartedAt: r.Started.UTC().Format(time.RFC3339), Output: r.Output, OwnerPasswordWaiting: r.HasOwner,
		Rehearsal: r.Options.Rehearsal, Wipe: r.Options.Wipe, OwnerEmail: r.Options.OwnerEmail}
	if !r.Finished.IsZero() {
		out.FinishedAt = r.Finished.UTC().Format(time.RFC3339)
	}
	switch {
	case len(r.Report) > 0:
		out.Report = string(r.Report)
	case len(r.ReviewDoc) > 0:
		out.Report = string(r.ReviewDoc)
	}
	out.Template = string(r.Template)
	return out
}

// GetImport is the Import page.
func (h *importSvc) GetImport(ctx context.Context, _ *connect.Request[osadminv1.GetImportRequest]) (*connect.Response[osadminv1.GetImportResponse], error) {
	s := h.s
	out := &osadminv1.GetImportResponse{}
	if mk, ok := s.Imported(); ok {
		out.Imported, out.ImportedBundle, out.ImportedAt, out.ImportedMode = true, mk.BundleID, mk.At.UTC().Format(time.RFC3339), mk.Mode
	}
	m, info, spec, err := s.importer()
	if err != nil {
		out.Reason = codes.Describe(err)
		return connect.NewResponse(out), nil
	}
	out.Available, out.Label = true, spec.Import.Label
	out.SetupDone = !out.Imported && s.setupDone(ctx, info, spec)
	if out.SetupDone {
		out.Reason = info.Title + "'s own setup is done, so its data didn't come from an import; factory-reset the box to import"
	}
	out.Recipient = m.Recipient()
	out.Open = out.Recipient != ""
	for _, f := range m.Files() {
		out.Files = append(out.Files, &osadminv1.ImportFile{Kind: string(f.Kind), Size: f.Size, UploadedAt: f.At.UTC().Format(time.RFC3339)})
	}
	runs, err := m.Runs()
	if err != nil {
		return nil, err
	}
	for _, r := range runs {
		out.Runs = append(out.Runs, runToWire(r))
		s.afterImport(ctx, spec, r)
	}
	if mk, ok := s.Imported(); ok {
		out.Imported, out.ImportedBundle, out.ImportedAt, out.ImportedMode = true, mk.BundleID, mk.At.UTC().Format(time.RFC3339), mk.Mode
		out.SetupDone, out.Reason = false, ""
	}
	return connect.NewResponse(out), nil
}

// afterImport, once per passed import step, marks the box imported and
// restarts what loads the imported state (the vault).
func (s *Server) afterImport(ctx context.Context, spec productspec.Spec, r productimport.Run) {
	if r.Step != productimport.Import || !r.Done || r.Exit != 0 {
		return
	}
	rep, ok := productimport.ParseImportReport(r.Report)
	if !ok {
		return
	}
	if mk, ok := s.Imported(); ok && mk.Job == r.Job {
		return
	}
	mk := productimport.Marker{BundleID: rep.BundleID, Job: r.Job, At: r.Finished, Mode: rep.Mode}
	if err := productimport.WriteMarker(s.importedMarker(), mk); err != nil {
		s.o.Logger.Error(err, "osadmin: the imported marker can't be written")
		return
	}
	s.write(osaudit.Entry{Actor: "system", Action: "import.done", Target: rep.BundleID, Detail: map[string]string{"job": r.Job, "mode": rep.Mode}}, nil)
	s.o.Logger.Info("osadmin: the product's data came from an import; imported-users mode", log.F("bundle", rep.BundleID), log.F("job", r.Job), log.F("mode", rep.Mode))
	for i := range spec.Import.Restart {
		ns, kind, name, _ := spec.Import.RestartRef(i)
		if s.o.Switches == nil || s.o.Switches.Restart == nil {
			break
		}
		if err := s.o.Switches.Restart(ctx, ns, kind, name); err != nil {
			s.o.Logger.Warn("osadmin: a workload didn't restart after the import; restart it before verify", log.F("workload", spec.Import.Restart[i]), log.F("error", err.Error()))
		}
	}
}

// OpenImport opens an import.
func (h *importSvc) OpenImport(ctx context.Context, _ *connect.Request[osadminv1.OpenImportRequest]) (*connect.Response[osadminv1.OpenImportResponse], error) {
	s, c := h.s, callFrom(ctx)
	m, info, spec, err := s.importer()
	if err != nil {
		return nil, err
	}
	if _, imported := s.Imported(); !imported && s.setupDone(ctx, info, spec) {
		return nil, codes.New(codes.NotAvailable, "%s's own setup is done; an import goes onto a box before it, so factory-reset the box first", info.Title)
	}
	if err := s.o.Switches.Set(ctx, spec, spec.Import.Switch, true); err != nil && codes.Is(err, codes.NotAvailable) {
		return nil, err
	}
	// A phased product holds after the phases the import writes to while
	// it's open (productspec.Import.After): asked again, the product's
	// probe stops the later phases and the box says maintenance.
	s.productWaitsAgain()
	rcpt, err := m.Open()
	if err != nil {
		return nil, err
	}
	c.note("import", "recipient", rcpt)
	s.o.Logger.Info("osadmin: import opened", log.F("by", c.session.Admin))
	return connect.NewResponse(&osadminv1.OpenImportResponse{Recipient: rcpt}), nil
}

// RunImportStep runs a step.
func (h *importSvc) RunImportStep(ctx context.Context, r *connect.Request[osadminv1.RunImportStepRequest]) (*connect.Response[osadminv1.RunImportStepResponse], error) {
	s, c := h.s, callFrom(ctx)
	q := r.Msg
	c.note("import step", "step", q.GetStep(), "rehearsal", strconv.FormatBool(q.GetRehearsal()), "wipe", strconv.FormatBool(q.GetWipe()), "owner", q.GetOwnerEmail())
	m, info, _, err := s.importer()
	if err != nil {
		return nil, err
	}
	if productimport.Step(q.GetStep()) == productimport.Verify {
		if ready, waiting := s.productReady(ctx); !ready {
			s.o.Logger.Info("osadmin: verify waits for the product to be ready", log.F("waiting", waiting))
			return nil, codes.New(codes.ProductNotReady, "%s isn't ready yet (%s); Verify runs once it is, so try again in a minute", info.Title, waiting)
		}
	}
	run, err := m.Start(productimport.Step(q.GetStep()), productimport.Options{Rehearsal: q.GetRehearsal(), Wipe: q.GetWipe(), OwnerEmail: q.GetOwnerEmail(),
		Parent: q.GetNewFolderParent(), Personal: q.GetPersonal()})
	if err != nil {
		return nil, err
	}
	c.note("import step", "step", q.GetStep(), "job", run.Job)
	return connect.NewResponse(&osadminv1.RunImportStepResponse{Job: run.Job}), nil
}

// TakeOwnerPassword shows the one-time password once.
func (h *importSvc) TakeOwnerPassword(ctx context.Context, r *connect.Request[osadminv1.TakeOwnerPasswordRequest]) (*connect.Response[osadminv1.TakeOwnerPasswordResponse], error) {
	s, c := h.s, callFrom(ctx)
	c.note("import owner password", "job", r.Msg.GetJob())
	m, _, _, err := s.importer()
	if err != nil {
		return nil, err
	}
	pw, err := m.TakeOwnerPassword(r.Msg.GetJob())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.TakeOwnerPasswordResponse{Password: pw}), nil
}

// CloseImport closes the import.
func (h *importSvc) CloseImport(ctx context.Context, _ *connect.Request[osadminv1.CloseImportRequest]) (*connect.Response[osadminv1.CloseImportResponse], error) {
	s, c := h.s, callFrom(ctx)
	m, _, spec, err := s.importer()
	if err != nil {
		return nil, err
	}
	if err := s.o.Switches.Set(ctx, spec, spec.Import.Switch, false); err != nil && codes.Is(err, codes.NotAvailable) {
		return nil, err
	}
	// The held phases come back; the box says running once they're ready.
	s.productWaitsAgain()
	s.boxChanged()
	if err := m.Close(); err != nil {
		return nil, err
	}
	c.note("import", "closed", "yes")
	s.o.Logger.Info("osadmin: import closed", log.F("by", c.session.Admin))
	return connect.NewResponse(&osadminv1.CloseImportResponse{}), nil
}

// handleImportUpload takes one import file as the request body.
func (s *Server) handleImportUpload(w http.ResponseWriter, r *http.Request) {
	kind := productimport.Kind(r.URL.Query().Get("kind"))
	entry := osaudit.Entry{Source: hostOf(r.RemoteAddr), Action: "import.upload", Target: string(kind)}
	sess, err := s.session(r.Header)
	if err == nil {
		entry.Actor = sess.Admin
		_, err = s.liveRole(sess)
	}
	if err == nil && subtle.ConstantTimeCompare([]byte(r.Header.Get(CSRFHeader)), []byte(sess.CSRF)) != 1 {
		err = codes.New(codes.AccessForbidden, "the request's CSRF token is missing or wrong; reload the page")
	}
	if err != nil {
		s.write(entry, err)
		http.Error(w, codes.Describe(err), http.StatusForbidden)
		return
	}
	m, _, _, err := s.importer()
	if err == nil {
		if _, ok := productimport.FileName(kind); !ok {
			err = codes.New(codes.NotAvailable, "an import takes a bundle, a mapping file, a proposal sheet or type rules, not %q", kind)
		}
	}
	var n int64
	if err == nil {
		n, err = m.Save(kind, http.MaxBytesReader(w, r.Body, productimport.MaxFile+1))
	}
	entry.Detail = map[string]string{"bytes": strconv.FormatInt(n, 10)}
	s.write(entry, err)
	if err != nil {
		s.o.Logger.Warn("osadmin: an import upload failed", log.F("kind", string(kind)), log.F("error", describe(err)))
		http.Error(w, describe(err), http.StatusBadRequest)
		return
	}
	s.o.Logger.Info("osadmin: import file uploaded", log.F("kind", string(kind)), log.F("bytes", n), log.F("by", sess.Admin))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"kind": kind, "bytes": n})
}
