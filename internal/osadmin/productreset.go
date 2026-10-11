// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
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
	Cluster(ctx context.Context) (productreset.Counts, error)
	Data(remove ...string) (int64, error)
}

// ResetBound is how long a product reset may take, whatever the closed
// shell that asked for it does: the product's quiesce, its objects going,
// k0s stopping (its stop-timeout) and the data going.
const ResetBound = 40 * time.Minute

// ResetProduct removes the installed product and its data
// (docs/upgrades.md#removing-the-product).
func (h *productSvc) ResetProduct(ctx context.Context, r *connect.Request[osadminv1.ResetProductRequest]) (*connect.Response[osadminv1.ResetProductResponse], error) {
	c := callFrom(ctx)
	out, step, err := h.s.resetProduct(ctx, c.by("product.reset"), r.Msg.GetConfirm())
	detail := []string{"version", out.GetVersion(), "namespaces", strconv.Itoa(int(out.GetNamespaces())), "objects", strconv.Itoa(int(out.GetObjects())),
		"bytes", strconv.FormatUint(out.GetBytesRemoved(), 10)}
	if step != "" {
		detail = append(detail, "step", step)
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
	if _, err := s.beginMaintenance(ctx, "product reset", edgefall.KindProductApply, by, nil); err != nil {
		return out, "", err
	}
	defer s.endMaintenance()
	// The reset finishes whatever the closed shell that asked does.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ResetBound)
	defer cancel()
	s.o.Logger.Info("osadmin: the product reset starts", log.F("product", info.Name), log.F("version", info.Version), log.F("by", by.Actor))
	step, err := s.removeProduct(ctx, out)
	detail := "namespaces=" + strconv.Itoa(int(out.GetNamespaces())) + " objects=" + strconv.Itoa(int(out.GetObjects())) + " bytes=" + strconv.FormatUint(out.GetBytesRemoved(), 10)
	s.historyFor(osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT, "reset", info.Version, by.Actor, err, detail)
	if err != nil {
		s.o.Logger.Error(err, "osadmin: the product reset stopped", log.F("step", step), log.F("product", info.Name))
		return out, step, err
	}
	s.o.Logger.Info("osadmin: the product is reset", log.F("product", info.Name), log.F("namespaces", out.GetNamespaces()), log.F("objects", out.GetObjects()), log.F("bytes", out.GetBytesRemoved()), log.F("staged", out.GetStagedVersion()))
	return out, "", nil
}

// removeProduct is the reset's steps: with k0s up (started when it isn't) the
// product stops in order and its objects go; k0s stops; the data and the
// records go; the slot is taken away and kept as the staged one; the
// product's ports close. A step that fails stops it there.
func (s *Server) removeProduct(ctx context.Context, out *osadminv1.ResetProductResponse) (string, error) {
	if !s.productRunning(ctx) {
		s.o.Logger.Info("osadmin: k0s doesn't run; it starts so the product's objects can go")
		if _, err := s.o.Services.Start(ctx, connect.NewRequest(&initv1.StartRequest{Name: ProductService})); err != nil {
			return "start", codes.New(codes.ProductReset, "k0s didn't start, so the product's objects can't be removed: %v", err)
		}
	}
	n, err := s.o.ProductReset.Cluster(ctx)
	out.Namespaces, out.Objects = uint32(min(n.Namespaces, 1<<31)), uint32(min(n.Objects, 1<<31)) // #nosec G115 -- clamped
	if err != nil {
		return "cluster", err
	}
	started := time.Now()
	if _, err := s.o.Services.Stop(ctx, connect.NewRequest(&initv1.StopRequest{Name: ProductService})); err != nil {
		return "stop", codes.New(codes.ProductReset, "k0s didn't stop: %v", err)
	}
	s.o.Logger.Info("osadmin: k0s stopped for the reset", log.F("ms", time.Since(started).Milliseconds()))
	s.productWaitsAgain()
	// The data goes while the product is still installed, so a reset that
	// stops here runs again from the start.
	dataBytes, err := s.o.ProductReset.Data(s.productRecords()...)
	out.BytesRemoved = uint64(max(dataBytes, 0)) // #nosec G115 -- not negative
	if err != nil {
		return "data", err
	}
	kept, slotBytes, err := s.slots().Uninstall()
	out.StagedVersion = kept
	out.BytesRemoved += uint64(max(slotBytes, 0)) // #nosec G115 -- not negative
	if err != nil {
		return "slot", codes.Wrap(codes.ProductReset, err)
	}
	if s.o.Network != nil {
		if _, err := s.o.Network.SetServicePorts(ctx, connect.NewRequest(&netdv1.SetServicePortsRequest{})); err != nil {
			s.o.Logger.Warn("osadmin: the product's ports didn't close; they close at the next boot", log.F("error", err.Error()))
		}
	}
	s.boxChanged()
	return "", nil
}
