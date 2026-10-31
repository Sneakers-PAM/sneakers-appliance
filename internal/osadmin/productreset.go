// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxname"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxsecrets"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/edgefall"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productinfo"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productreset"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productswitch"
)

// ProductResetter removes the installed product (productreset.Reset on
// the box): Cluster with k0s up, then, once k0s has stopped, Data, which
// also removes the box's records of the product it's given.
type ProductResetter interface {
	Cluster(ctx context.Context, removing func() error) (productreset.Counts, error)
	Data(remove ...string) (int64, error)
}

// resetWhat is the reset's name for beginMaintenance.
const resetWhat = "product reset"

// ResetBound is how long a product reset may take, whatever the closed
// shell that asked for it does: the product's quiesce, its objects going,
// k0s stopping (its stop-timeout) and the data going.
const ResetBound = 40 * time.Minute

// ResetProduct removes the installed product and its data
// (docs/upgrades.md#removing-the-product).
func (h *productSvc) ResetProduct(ctx context.Context, r *connect.Request[osadminv1.ResetProductRequest]) (*connect.Response[osadminv1.ResetProductResponse], error) {
	c := callFrom(ctx)
	by := c.by("product.reset")
	by.KeyFP = c.keyFP
	out, step, err := h.s.resetProduct(ctx, by, r.Msg.GetConfirm())
	detail := []string{"version", out.GetVersion(), "namespaces", strconv.Itoa(int(out.GetNamespaces())), "objects", strconv.Itoa(int(out.GetObjects())),
		"bytes", strconv.FormatUint(out.GetBytesRemoved(), 10)}
	if step != "" {
		detail = append(detail, "step", step)
	}
	if err == nil {
		detail = append(detail, "event", "finished")
	}
	c.note(out.GetProductTitle(), detail...)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(out), nil
}

// resetNames are the words that confirm a reset: the product's name, and
// the box's host name (whole and its first label) and its own name.
func (s *Server) resetNames(ctx context.Context, info productinfo.Info) []string {
	names := []string{info.Name}
	if s.o.Network != nil {
		if st, err := s.o.Network.Status(ctx, connect.NewRequest(&netdv1.StatusRequest{})); err == nil {
			if h := strings.TrimSuffix(strings.ToLower(st.Msg.GetHostname()), "."); h != "" {
				short, _, _ := strings.Cut(h, ".")
				names = append(names, h, short)
			}
		}
	}
	if b, err := os.ReadFile(boxname.Path(s.o.Paths.State)); err == nil {
		if own := strings.TrimSpace(string(b)); own != "" {
			names = append(names, own)
		}
	}
	return names
}

// productRecords are the box's records of the installed product that go
// with it: the Secrets it made for it (escrowed keys come back from key
// custody when it's installed again), its switches, the import's files
// and marker, and which one-time values were used.
func (s *Server) productRecords() []string {
	platform := filepath.Join(s.o.Paths.State, "platform")
	return []string{
		filepath.Join(platform, boxsecrets.ValuesFile), filepath.Join(platform, productswitch.StateFile), s.importedMarker(),
		filepath.Join(s.o.Paths.State, importDir), filepath.Join(s.o.Paths.APIDir(), exposedDir),
	}
}

// resetProduct checks the reset may go ahead, then removes the product in
// its steps, answering the step it stopped at.
func (s *Server) resetProduct(ctx context.Context, by osaudit.Entry, confirm string) (*osadminv1.ResetProductResponse, string, error) {
	sl := s.slots()
	info := productinfo.Installed(sl.Dir)
	out := &osadminv1.ResetProductResponse{Product: info.Name, ProductTitle: info.Title, Version: info.Version}
	if out.ProductTitle == "" {
		out.ProductTitle = "product"
	}
	if s.o.ProductReset == nil || s.o.Services == nil {
		return out, "", notAvailable()
	}
	if !info.Present() {
		return out, "", codes.New(codes.ProductNotInstalled, "no product is installed, so there's nothing to reset; install one from the Product card on Updates")
	}
	typed := strings.ToLower(strings.TrimSpace(confirm))
	if typed == "" || !slices.Contains(s.resetNames(ctx, info), typed) {
		return out, "", codes.New(codes.AccessConfirm, "type %s, the product's name, or the box's host name to confirm", info.Name)
	}
	if s.Maintenance() || s.UpdateBusy() || s.productComingUp() {
		return out, "", codes.New(codes.UpgradeBusy, "an update is coming in, being staged or applied, or the product is coming up; reset once it's done")
	}
	if _, err := s.beginMaintenance(ctx, resetWhat, edgefall.KindProductApply, by, nil); err != nil {
		return out, "", err
	}
	defer s.endMaintenance()
	// The reset finishes whatever the closed shell that asked does.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ResetBound)
	defer cancel()
	rec := s.readResetRecord()
	if rec == nil {
		rec = &resetRecord{Product: info.Name, Title: out.ProductTitle, Version: info.Version, Actor: by.Actor, Started: s.o.Clock.Now().UTC(), Step: resetQuiesce}
		if err := s.saveResetStep(rec, resetQuiesce); err != nil {
			return out, "record", codes.New(codes.ProductReset, "the reset can't be recorded, so nothing was removed: %v", err)
		}
	}
	started := by
	started.Target, started.Detail = out.ProductTitle, maps.Clone(by.Detail)
	if started.Detail == nil {
		started.Detail = map[string]string{}
	}
	started.Detail["event"], started.Detail["version"], started.Detail["from"] = "started", info.Version, rec.Step
	s.write(started, nil)
	s.o.Logger.Info("osadmin: the product reset starts", log.F("product", info.Name), log.F("version", info.Version), log.F("by", by.Actor), log.F("from", rec.Step))
	s.resetRuns(true)
	defer s.resetRuns(false)
	step, err := s.removeProduct(ctx, out, rec)
	detail := "namespaces=" + strconv.Itoa(int(out.GetNamespaces())) + " objects=" + strconv.Itoa(int(out.GetObjects())) + " bytes=" + strconv.FormatUint(out.GetBytesRemoved(), 10)
	s.historyFor(osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT, "reset", info.Version, by.Actor, err, detail)
	if err != nil {
		s.o.Logger.Error(err, "osadmin: the product reset stopped", log.F("step", step), log.F("product", info.Name))
		return out, step, err
	}
	s.o.Logger.Info("osadmin: the product is reset", log.F("product", info.Name), log.F("namespaces", out.GetNamespaces()), log.F("objects", out.GetObjects()), log.F("bytes", out.GetBytesRemoved()), log.F("staged", out.GetStagedVersion()))
	return out, "", nil
}

// removeProduct is the reset's steps, from the one rec says: with k0s up
// (started when it isn't) the product stops in order and its objects go;
// k0s stops; the data and the records go; the slot is taken away and kept
// as the staged one; the product's ports close. Each is on the disk before
// it starts. A step that fails stops it there, and rec holds the product
// until the reset runs again and goes on from that step; one that fails
// before anything was removed drops rec.
func (s *Server) removeProduct(ctx context.Context, out *osadminv1.ResetProductResponse, rec *resetRecord) (string, error) {
	if rec.Step == resetQuiesce || rec.Step == resetCluster {
		if !s.productRunning(ctx) {
			s.o.Logger.Info("osadmin: k0s doesn't run; it starts so the product's objects can go")
			if _, err := s.o.Services.Start(ctx, connect.NewRequest(&initv1.StartRequest{Name: ProductService})); err != nil {
				s.dropUntouched(rec)
				return "start", codes.New(codes.ProductReset, "k0s didn't start, so the product's objects can't be removed: %v", err)
			}
		}
		n, err := s.o.ProductReset.Cluster(ctx, func() error { return s.saveResetStep(rec, resetCluster) })
		out.Namespaces, out.Objects = uint32(min(n.Namespaces, 1<<31)), uint32(min(n.Objects, 1<<31)) // #nosec G115 -- clamped
		if err != nil {
			s.dropUntouched(rec)
			return "cluster", err
		}
	}
	// Also for a reset going on past k0s: its stop ends k0s's retries of a
	// start the record refused.
	started := time.Now()
	if _, err := s.o.Services.Stop(ctx, connect.NewRequest(&initv1.StopRequest{Name: ProductService})); err != nil {
		return "stop", codes.New(codes.ProductReset, "k0s didn't stop: %v", err)
	}
	s.o.Logger.Info("osadmin: k0s stopped for the reset", log.F("ms", time.Since(started).Milliseconds()))
	s.productWaitsAgain()
	if rec.Step != resetSlot {
		if err := s.saveResetStep(rec, resetData); err != nil {
			return "data", codes.Wrap(codes.ProductReset, err)
		}
		// The data goes while the product is still installed, so a reset
		// that stops here goes on from here.
		dataBytes, err := s.o.ProductReset.Data(s.productRecords()...)
		out.BytesRemoved = uint64(max(dataBytes, 0)) // #nosec G115 -- not negative
		if err != nil {
			return "data", err
		}
		if err := s.saveResetStep(rec, resetSlot); err != nil {
			return "slot", codes.Wrap(codes.ProductReset, err)
		}
	}
	kept, slotBytes, err := s.slots().Uninstall()
	out.StagedVersion = kept
	if kept != "" {
		s.keepResetBundle(kept)
	}
	out.BytesRemoved += uint64(max(slotBytes, 0)) // #nosec G115 -- not negative
	if err != nil {
		return "slot", codes.Wrap(codes.ProductReset, err)
	}
	if err := s.dropResetRecord(); err != nil {
		return "record", codes.Wrap(codes.ProductReset, err)
	}
	if s.o.Network != nil {
		if _, err := s.o.Network.SetServicePorts(ctx, connect.NewRequest(&netdv1.SetServicePortsRequest{})); err != nil {
			s.o.Logger.Warn("osadmin: the product's ports didn't close; they close at the next boot", log.F("error", err.Error()))
		}
	}
	s.boxChanged()
	return "", nil
}

// A reset's steps, as its record names them: each is written before it
// starts, so the record never says less than what may have happened.
const (
	// resetQuiesce: the product is stopping and nothing is removed yet.
	resetQuiesce = "quiesce"
	// resetCluster: the product's objects are going.
	resetCluster = "cluster"
	// resetData: k0s has stopped and the data and records are going.
	resetData = "data"
	// resetSlot: the data has gone and the slot is going.
	resetSlot = "slot"
)

// resetRecord is a reset under way, on the state volume (RecordFile), from
// before it removes anything until it's done. k0s-interim refuses to start
// the product on it, so a reset cut off by a reboot or a crash never comes
// back as an empty product with new secrets.
type resetRecord struct {
	Product string    `json:"product"`
	Title   string    `json:"title"`
	Version string    `json:"version"`
	Actor   string    `json:"actor"`
	Started time.Time `json:"started"`
	Step    string    `json:"step"`
}

func (s *Server) resetRecordPath() string {
	return filepath.Join(s.o.Paths.State, "platform", productreset.RecordFile)
}

// readResetRecord is the reset under way, or nil. One that doesn't parse
// still holds the product, as a reset that may have removed something.
func (s *Server) readResetRecord() *resetRecord {
	b, err := os.ReadFile(s.resetRecordPath()) // #nosec G304 -- the box's own record
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	rec := &resetRecord{}
	if err == nil {
		err = json.Unmarshal(b, rec)
	}
	if err != nil || rec.Step == "" {
		s.o.Logger.Warn("osadmin: the product reset's record doesn't read; taking it as cut off part-way", log.F("error", fmt.Sprint(err)))
		return &resetRecord{Product: "<product>", Title: "The product", Step: resetCluster}
	}
	return rec
}

// saveResetStep puts step on the disk, through to the state volume.
func (s *Server) saveResetStep(rec *resetRecord, step string) error {
	rec.Step = step
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.resetRecordPath())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := writeAtomic(s.resetRecordPath(), b); err != nil {
		return err
	}
	s.o.Logger.Info("osadmin: the product reset's record", log.F("step", step))
	return syncDir(dir)
}

func (s *Server) dropResetRecord() error {
	if err := os.Remove(s.resetRecordPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncDir(filepath.Dir(s.resetRecordPath()))
}

// dropUntouched drops rec after a failure before anything was removed: the
// product is whole, so nothing holds it.
func (s *Server) dropUntouched(rec *resetRecord) {
	if rec.Step != resetQuiesce {
		return
	}
	if err := s.dropResetRecord(); err != nil {
		s.o.Logger.Error(err, "osadmin: the product reset's record didn't go")
	}
}

func syncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- a directory on the state volume
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// resetRuns says a reset is running, to this process and, through
// ResetRunningFile, to k0s-interim: the reset may start k0s on its record.
func (s *Server) resetRuns(on bool) {
	s.resetting.Store(on)
	if s.o.ResetRunningFile == "" {
		return
	}
	var err error
	if on {
		err = os.WriteFile(s.o.ResetRunningFile, nil, 0o600)
	} else {
		err = os.Remove(s.o.ResetRunningFile)
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.o.Logger.Warn("osadmin: the reset's running mark didn't change", log.F("on", on), log.F("error", err.Error()))
	}
}

// resetCutOffNote says why the product can't start, or "" when no reset
// was cut off.
func (s *Server) resetCutOffNote() string {
	if s.resetting.Load() {
		return ""
	}
	rec := s.readResetRecord()
	if rec == nil {
		return ""
	}
	return fmt.Sprintf("A product reset was cut off part-way, so %s can't start. An owner finishes it with %s reset over SSH.", strings.TrimSpace(rec.Title+" "+rec.Version), rec.Product)
}

// ResumeProductReset settles a reset that was cut off (a dropped session
// can't do that; a reboot, a power cut or a crash can); accessd calls it at
// start, and k0s-interim has refused to start the product until now. Cut
// off before anything went, the reset is dropped and the product starts
// again. With the slot gone, only the record was left, and it's finished.
// Otherwise the product is held, and says so, until an owner runs the
// reset again, which goes on from the step it was cut off at.
func (s *Server) ResumeProductReset(ctx context.Context) {
	s.resetRuns(false)
	rec := s.readResetRecord()
	if rec == nil {
		return
	}
	entry := osaudit.Entry{Actor: "system", Action: "product.reset", Target: rec.Title}
	detail := map[string]string{"version": rec.Version, "started_by": rec.Actor}
	settled := func(event, history string, err error) {
		if derr := s.dropResetRecord(); derr != nil {
			s.o.Logger.Error(derr, "osadmin: the product reset's record didn't go")
			return
		}
		detail["event"], entry.Detail = event, detail
		s.write(entry, nil)
		s.historyFor(osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT, "reset", rec.Version, rec.Actor, err, history)
	}
	st := s.slots().Status()
	switch {
	case st.Installed == "":
		s.o.Logger.Info("osadmin: a product reset was cut off with the slot gone; it's finished", log.F("step", rec.Step))
		if st.Staged != "" {
			s.keepResetBundle(st.Staged)
		}
		settled("finished", "finished at the next start", nil)
	case rec.Step == resetQuiesce:
		s.o.Logger.Warn("osadmin: a product reset was cut off before it removed anything; the product starts again", log.F("version", rec.Version))
		s.stopForReset(ctx)
		settled("abandoned", "cut off before anything was removed; the product stays", codes.New(codes.ProductReset, "the reset was cut off"))
		s.productWaitsAgain()
		if err := s.startProduct(ctx); err != nil {
			s.o.Logger.Error(err, "osadmin: the product didn't start again after the abandoned reset")
		}
	default:
		s.o.Logger.Warn("osadmin: a product reset was cut off part-way; the product is held until an owner finishes it", log.F("step", rec.Step), log.F("version", rec.Version))
		s.stopForReset(ctx)
	}
	s.boxChanged()
}

// stopForReset stops k0s, which also ends its retries of the start the
// record refuses. It's still running when only accessd restarted.
func (s *Server) stopForReset(ctx context.Context) {
	if s.o.Services == nil {
		return
	}
	if _, err := s.o.Services.Stop(ctx, connect.NewRequest(&initv1.StopRequest{Name: ProductService})); err != nil {
		s.o.Logger.Error(err, "osadmin: k0s didn't stop for the cut-off reset")
	}
}
