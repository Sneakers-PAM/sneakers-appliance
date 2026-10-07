// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/weblogin"
)

type accessSvc struct {
	osadminv1connect.UnimplementedAccessServiceHandler
	s *Server
}

func (h *accessSvc) ListAdmins(context.Context, *connect.Request[osadminv1.ListAdminsRequest]) (*connect.Response[osadminv1.ListAdminsResponse], error) {
	st := h.s.o.Access.Read()
	out := &osadminv1.ListAdminsResponse{
		HostKeys: h.s.hostKeys(),
		ElevationPolicy: &osadminv1.ElevationPolicy{
			MaxMinutes: int32(min(st.ElevationPolicy.MaxMinutes, 1<<30)), DefaultMinutes: int32(min(st.ElevationPolicy.DefaultMinutes, 1<<30)), // #nosec G115 -- clamped
			SelfApprovalWhenSingleOwner: st.ElevationPolicy.SelfApprovalWhenSingleOwner,
		},
	}
	for _, a := range st.Admins {
		out.Admins = append(out.Admins, adminToWire(a))
	}
	q := st.EffectiveQuorum()
	out.Quorum = &osadminv1.Quorum{Members: q.Members, Required: int32(min(q.Required, 1<<30)), Configured: q.Configured} // #nosec G115 -- clamped
	return connect.NewResponse(out), nil
}

func adminToWire(a access.Admin) *osadminv1.Admin {
	w := &osadminv1.Admin{Name: a.Name, Uid: int32(min(a.UID, 1<<30)), Role: roleToWire(a.Role), Created: timestamppb.New(a.Created), CreatedBy: a.CreatedBy} // #nosec G115 -- clamped
	if a.ApprovalHoldUntil != nil {
		w.ApprovalHoldUntil = timestamppb.New(*a.ApprovalHoldUntil)
	}
	for _, k := range a.Keys {
		w.Keys = append(w.Keys, keyToWire(k))
	}
	return w
}

func keyToWire(k access.AdminKey) *osadminv1.Key {
	w := &osadminv1.Key{Fingerprint: k.Fingerprint, Type: k.Type, Comment: k.Comment, Added: timestamppb.New(k.Added), AddedBy: k.AddedBy, Via: k.Via}
	if k.LastUsed != nil {
		w.LastUsed = timestamppb.New(*k.LastUsed)
	}
	return w
}

// hostKeys reads the SSH host public keys; a box before step 3 has none.
func (s *Server) hostKeys() []*osadminv1.HostKey {
	paths, _ := filepath.Glob(filepath.Join(s.o.Paths.SSHDir(), "ssh_host_*_key.pub"))
	sort.Strings(paths)
	var out []*osadminv1.HostKey
	for _, p := range paths {
		b, err := os.ReadFile(p) // #nosec G304 -- a host key under the state volume's ssh directory
		if err != nil {
			s.o.Logger.Warn("osadmin: host key unreadable", log.F("path", p), log.F("error", err.Error()))
			continue
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			s.o.Logger.Warn("osadmin: host key doesn't parse", log.F("path", p))
			continue
		}
		out = append(out, &osadminv1.HostKey{Type: pk.Type(), Fingerprint: ssh.FingerprintSHA256(pk)})
	}
	return out
}

func (h *accessSvc) AddAdmin(ctx context.Context, r *connect.Request[osadminv1.AddAdminRequest]) (*connect.Response[osadminv1.AddAdminResponse], error) {
	c := callFrom(ctx)
	c.note(r.Msg.GetName(), "role", r.Msg.GetRole().String())
	role, err := roleFromWire(r.Msg.GetRole())
	if err != nil {
		return nil, err
	}
	var key *access.Key
	if strings.TrimSpace(r.Msg.GetPublicKey()) != "" {
		k, err := access.ParseLoginKey(r.Msg.GetPublicKey())
		if err != nil {
			return nil, err
		}
		key = &k
		c.note(r.Msg.GetName(), "key", k.Fingerprint)
	}
	now := h.s.o.Clock.Now().UTC()
	var added access.Admin
	err = h.s.o.Access.Update(func(st *access.State) error {
		if _, taken := st.Admin(r.Msg.GetName()); taken {
			return codes.New(codes.AccessName, "there is already an admin named %q", r.Msg.GetName())
		}
		a := st.AddAdmin(r.Msg.GetName(), role, c.session.Admin, now)
		if key != nil {
			a.Keys = append(a.Keys, access.AdminKey{Key: *key, Added: now, AddedBy: c.session.Admin, Via: access.ViaOSAdmin})
		}
		added = *a
		return nil
	})
	if err != nil {
		return nil, err
	}
	h.s.o.Logger.Info("osadmin: admin added", log.F("admin", added.Name), log.F("role", string(role)), log.F("by", c.session.Admin))
	return connect.NewResponse(&osadminv1.AddAdminResponse{Admin: adminToWire(added)}), nil
}

func (h *accessSvc) RemoveAdmin(ctx context.Context, r *connect.Request[osadminv1.RemoveAdminRequest]) (*connect.Response[osadminv1.RemoveAdminResponse], error) {
	c := callFrom(ctx)
	name := r.Msg.GetName()
	c.note(name)
	err := h.s.o.Access.Update(func(st *access.State) error {
		i := slices.IndexFunc(st.Admins, func(a access.Admin) bool { return a.Name == name })
		if i < 0 {
			return codes.New(codes.AccessName, "there is no admin named %q", name)
		}
		st.Admins = slices.Delete(st.Admins, i, i+1)
		return nil
	})
	if err != nil {
		return nil, err
	}
	n := h.s.sessions.EndWhere(func(s weblogin.Session) bool { return s.Admin == name })
	h.s.o.Logger.Info("osadmin: admin removed", log.F("admin", name), log.F("sessionsEnded", n), log.F("by", c.session.Admin))
	return connect.NewResponse(&osadminv1.RemoveAdminResponse{}), nil
}

func (h *accessSvc) SetRole(ctx context.Context, r *connect.Request[osadminv1.SetRoleRequest]) (*connect.Response[osadminv1.SetRoleResponse], error) {
	c := callFrom(ctx)
	c.note(r.Msg.GetName(), "role", r.Msg.GetRole().String())
	role, err := roleFromWire(r.Msg.GetRole())
	if err != nil {
		return nil, err
	}
	err = h.s.o.Access.Update(func(st *access.State) error {
		a, ok := st.Admin(r.Msg.GetName())
		if !ok {
			return codes.New(codes.AccessName, "there is no admin named %q", r.Msg.GetName())
		}
		a.Role = role
		return nil
	})
	if err != nil {
		return nil, err
	}
	h.s.o.Logger.Info("osadmin: role changed", log.F("admin", r.Msg.GetName()), log.F("role", string(role)), log.F("by", c.session.Admin))
	return connect.NewResponse(&osadminv1.SetRoleResponse{}), nil
}

// mayManageKeys: an admin manages their own keys, an owner anyone's.
func mayManageKeys(c *call, admin string) error {
	if c.role != access.RoleOwner && admin != c.session.Admin {
		return codes.New(codes.AccessForbidden, "an admin manages only their own keys")
	}
	return nil
}

func (h *accessSvc) AddKey(ctx context.Context, r *connect.Request[osadminv1.AddKeyRequest]) (*connect.Response[osadminv1.AddKeyResponse], error) {
	c := callFrom(ctx)
	c.note(r.Msg.GetAdmin())
	if err := mayManageKeys(c, r.Msg.GetAdmin()); err != nil {
		return nil, err
	}
	k, err := access.ParseLoginKey(r.Msg.GetPublicKey())
	if err != nil {
		return nil, err
	}
	c.note(r.Msg.GetAdmin(), "key", k.Fingerprint)
	ak := access.AdminKey{Key: k, Added: h.s.o.Clock.Now().UTC(), AddedBy: c.session.Admin, Via: access.ViaOSAdmin}
	err = h.s.o.Access.Update(func(st *access.State) error {
		a, ok := st.Admin(r.Msg.GetAdmin())
		if !ok {
			return codes.New(codes.AccessName, "there is no admin named %q", r.Msg.GetAdmin())
		}
		a.Keys = append(a.Keys, ak)
		return nil
	})
	if err != nil {
		return nil, err
	}
	h.s.o.Logger.Info("osadmin: key added", log.F("admin", r.Msg.GetAdmin()), log.F("key", k.Fingerprint), log.F("by", c.session.Admin))
	return connect.NewResponse(&osadminv1.AddKeyResponse{Key: keyToWire(ak)}), nil
}

func (h *accessSvc) RemoveKey(ctx context.Context, r *connect.Request[osadminv1.RemoveKeyRequest]) (*connect.Response[osadminv1.RemoveKeyResponse], error) {
	c := callFrom(ctx)
	admin, fp := r.Msg.GetAdmin(), r.Msg.GetFingerprint()
	c.note(admin, "key", fp)
	if err := mayManageKeys(c, admin); err != nil {
		return nil, err
	}
	err := h.s.o.Access.Update(func(st *access.State) error {
		a, ok := st.Admin(admin)
		if !ok {
			return codes.New(codes.AccessName, "there is no admin named %q", admin)
		}
		i := slices.IndexFunc(a.Keys, func(k access.AdminKey) bool { return k.Fingerprint == fp })
		if i < 0 {
			return codes.New(codes.AccessKeyType, "%s has no key %s", admin, fp)
		}
		a.Keys = slices.Delete(a.Keys, i, i+1)
		return nil
	})
	if err != nil {
		return nil, err
	}
	n := h.s.sessions.EndWhere(func(s weblogin.Session) bool { return s.Admin == admin && s.KeyFP == fp })
	h.s.o.Logger.Info("osadmin: key removed", log.F("admin", admin), log.F("key", fp), log.F("sessionsEnded", n), log.F("by", c.session.Admin))
	return connect.NewResponse(&osadminv1.RemoveKeyResponse{}), nil
}

func (h *accessSvc) SetElevationPolicy(ctx context.Context, r *connect.Request[osadminv1.SetElevationPolicyRequest]) (*connect.Response[osadminv1.SetElevationPolicyResponse], error) {
	c := callFrom(ctx)
	p := r.Msg.GetPolicy()
	c.note("elevation-policy", "maxMinutes", itoa(int(p.GetMaxMinutes())), "defaultMinutes", itoa(int(p.GetDefaultMinutes())))
	maxM, defM := int(p.GetMaxMinutes()), int(p.GetDefaultMinutes())
	if maxM < 15 || maxM > 240 || defM < 15 || defM > maxM {
		return nil, codes.New(codes.AccessForbidden, "elevation lasts 15 to 240 minutes, and the default can't exceed the maximum")
	}
	err := h.s.o.Access.Update(func(st *access.State) error {
		st.ElevationPolicy = access.Policy{MaxMinutes: maxM, DefaultMinutes: defM, SelfApprovalWhenSingleOwner: p.GetSelfApprovalWhenSingleOwner()}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.SetElevationPolicyResponse{}), nil
}

func itoa(n int) string { return strconv.Itoa(n) }

func (h *accessSvc) SetQuorum(ctx context.Context, r *connect.Request[osadminv1.SetQuorumRequest]) (*connect.Response[osadminv1.SetQuorumResponse], error) {
	c := callFrom(ctx)
	roster := access.QuorumRoster{Members: r.Msg.GetMembers(), Required: int(r.Msg.GetRequired())}
	c.note("quorum", "members", strings.Join(roster.Members, ","), "required", itoa(roster.Required))
	err := h.s.o.Access.Update(func(st *access.State) error {
		if err := access.ValidateQuorum(*st, roster); err != nil {
			return err
		}
		st.Quorum = &roster
		return nil
	})
	if err != nil {
		return nil, err
	}
	h.s.o.Logger.Info("osadmin: quorum roster set", log.F("members", len(roster.Members)), log.F("required", roster.Required), log.F("by", c.session.Admin))
	return connect.NewResponse(&osadminv1.SetQuorumResponse{}), nil
}
