// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productinfo"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// ExposedReader reads in the installed product's cluster as the
// appliance's own service account, whose Role names only the declared
// Secrets (productspec.RBAC).
type ExposedReader interface {
	SecretKey(ctx context.Context, namespace, name, key string) (string, error)
	ServiceGet(ctx context.Context, namespace, proxy, path string) ([]byte, error)
}

// exposedDir keeps a marker per consumed one-time value.
const exposedDir = "exposed"

type productSvc struct {
	osadminv1connect.UnimplementedProductServiceHandler
	s *Server
}

// installedSpec is the installed product and its product.yaml; the zero
// values with none, or a slot whose product.yaml can't be read (it was
// checked when it was staged, so that's logged, not shown).
func (s *Server) installedSpec() (productinfo.Info, productspec.Spec) {
	info := productinfo.Installed(s.slots().Dir)
	if !info.Present() {
		return info, productspec.Spec{}
	}
	spec, err := productspec.Load(s.slots().Current())
	if err != nil {
		s.o.Logger.Error(err, "osadmin: the installed product's product.yaml can't be read; it exposes nothing")
		return info, productspec.Spec{}
	}
	return info, spec
}

func roleWord(r access.Role) string {
	if r == access.RoleOwner {
		return productspec.RoleOwner
	}
	return productspec.RoleAdmin
}

func rolesToWire(roles []string) []osadminv1.Role {
	out := make([]osadminv1.Role, 0, len(roles))
	for _, r := range roles {
		if r == productspec.RoleOwner {
			out = append(out, osadminv1.Role_ROLE_OWNER)
		} else {
			out = append(out, osadminv1.Role_ROLE_ADMIN)
		}
	}
	return out
}

func (s *Server) consumedMarker(product, name string) string {
	return filepath.Join(s.o.Paths.APIDir(), exposedDir, product+"-"+name+".consumed")
}

func (s *Server) consumed(product string, v productspec.ExposedValue) bool {
	if !v.OneTime {
		return false
	}
	_, err := os.Stat(s.consumedMarker(product, v.Name))
	return err == nil
}

func (s *Server) entryWire(ctx context.Context, product string, v productspec.ExposedValue) *osadminv1.ExposedValue {
	return &osadminv1.ExposedValue{Name: v.Name, Label: v.Label, OneTime: v.OneTime, Consumed: s.consumed(product, v), Roles: rolesToWire(v.Roles), Link: v.LinkFor(s.boxHost(ctx))}
}

// ListExposedValues lists what the caller's role may read.
func (h *productSvc) ListExposedValues(ctx context.Context, _ *connect.Request[osadminv1.ListExposedValuesRequest]) (*connect.Response[osadminv1.ListExposedValuesResponse], error) {
	info, spec := h.s.installedSpec()
	role := roleWord(callFrom(ctx).role)
	out := &osadminv1.ListExposedValuesResponse{Product: info.Name, ProductTitle: info.Title}
	for _, v := range spec.ExposedValues {
		if v.Allows(role) {
			out.Values = append(out.Values, h.s.entryWire(ctx, info.Name, v))
		}
	}
	return connect.NewResponse(out), nil
}

// GetExposedValue reads one declared value, for a role the bundle lists.
func (h *productSvc) GetExposedValue(ctx context.Context, r *connect.Request[osadminv1.GetExposedValueRequest]) (*connect.Response[osadminv1.GetExposedValueResponse], error) {
	s, c := h.s, callFrom(ctx)
	name := r.Msg.GetName()
	c.note("product value", "name", name)
	info, spec := s.installedSpec()
	v, ok := spec.Find(name)
	if !ok {
		s.o.Logger.Warn("osadmin: a read of a value the product doesn't expose; refused", log.F("name", name), log.F("admin", c.session.Admin))
		return nil, codes.New(codes.AccessForbidden, "the installed product exposes no value named %q", name)
	}
	if !v.Allows(roleWord(c.role)) {
		return nil, codes.New(codes.AccessForbidden, "%s's %s is for %v only", info.Title, v.Name, v.Roles)
	}
	out := &osadminv1.GetExposedValueResponse{ProductTitle: info.Title}
	if s.consumed(info.Name, v) {
		out.Entry = s.entryWire(ctx, info.Name, v)
		c.note("product value", "name", name, "state", "consumed")
		return connect.NewResponse(out), nil
	}
	if s.o.Exposed == nil {
		return nil, notAvailable()
	}
	if v.OneTime {
		held, err := s.signalHolds(ctx, v)
		switch {
		case err != nil:
			s.o.Logger.Info("osadmin: the product's consumed_when signal isn't known yet; the value is still shown", log.F("name", name), log.F("error", err.Error()))
		case held:
			if err := s.consume(info.Name, v); err != nil {
				return nil, err
			}
			s.o.Logger.Info("osadmin: a one-time product value is consumed", log.F("name", name))
			out.Entry = s.entryWire(ctx, info.Name, v)
			c.note("product value", "name", name, "state", "consumed", "consumed", "now")
			return connect.NewResponse(out), nil
		}
	}
	val, err := s.o.Exposed.SecretKey(ctx, v.Namespace(), v.SecretName(), v.Key)
	if err != nil {
		s.o.Logger.Warn("osadmin: a product value can't be read", log.F("name", name), log.F("error", err.Error()))
		return nil, codes.New(codes.ProductValueUnavailable, "%s's %s can't be read yet: %v", info.Title, v.Name, err)
	}
	out.Entry, out.Value = s.entryWire(ctx, info.Name, v), val
	c.note("product value", "name", name, "state", "shown")
	return connect.NewResponse(out), nil
}

func (s *Server) signalHolds(ctx context.Context, v productspec.ExposedValue) (bool, error) {
	sig := v.ConsumedWhen
	b, err := s.o.Exposed.ServiceGet(ctx, sig.Namespace(), sig.ProxyName(), sig.Path)
	if err != nil {
		return false, err
	}
	var answer map[string]any
	if err := json.Unmarshal(b, &answer); err != nil {
		return false, errors.New("the signal's answer isn't a JSON object")
	}
	return sig.Holds(answer), nil
}

func (s *Server) consume(product string, v productspec.ExposedValue) error {
	p := s.consumedMarker(product, v.Name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return writeAtomic(p, nil)
}
