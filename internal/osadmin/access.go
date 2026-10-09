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
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevation"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/weblogin"
)

type accessSvc struct {
	osadminv1connect.UnimplementedAccessServiceHandler
	s *Server
}

func (h *accessSvc) ListAdmins(ctx context.Context, _ *connect.Request[osadminv1.ListAdminsRequest]) (*connect.Response[osadminv1.ListAdminsResponse], error) {
	st := h.s.o.Access.Read()
	out := &osadminv1.ListAdminsResponse{HostKeys: h.s.hostKeys(), AccessPolicy: policyToWireAccess(st.AccessPolicy.Effective())}
	if k := h.s.o.RootKey; k != nil {
		out.RootKey = &osadminv1.HostKey{Type: k.PublicKey().Type(), Fingerprint: k.Fingerprint()}
		out.UserCaPublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k.PublicKey())))
		out.HostCa = &osadminv1.HostKey{Type: k.HostCAPublicKey().Type(), Fingerprint: ssh.FingerprintSHA256(k.HostCAPublicKey())}
		out.KnownHosts, _ = h.s.knownHosts(ctx)
	}
	now := h.s.o.Clock.Now()
	for _, a := range st.Admins {
		w := adminToWire(a)
		w.RootOperator = st.IsRootOperator(a.Name)
		if h.s.o.Lockout != nil {
			ls := h.s.o.Lockout.State(a.Name, now)
			w.FailedAttempts, w.LockedUntilUnlocked = int32(min(ls.Failures, 1<<30)), ls.UntilUnlocked // #nosec G115 -- clamped
			if !ls.LockedUntil.IsZero() {
				w.LockedUntil = timestamppb.New(ls.LockedUntil)
			}
		}
		out.Admins = append(out.Admins, w)
	}
	q := st.EffectiveQuorum()
	out.Quorum = &osadminv1.Quorum{Members: q.Members, Required: int32(min(q.Required, 1<<30)), Configured: q.Configured} // #nosec G115 -- clamped
	for _, r := range st.RevokedKeys {
		keyType, _, _ := strings.Cut(r.PublicKey, " ")
		out.RevokedKeys = append(out.RevokedKeys, &osadminv1.RevokedKey{Fingerprint: r.Fingerprint, Type: keyType, Admin: r.Admin, Revoked: timestamppb.New(r.Revoked), RevokedBy: r.By()})
	}
	return connect.NewResponse(out), nil
}

func adminToWire(a access.Admin) *osadminv1.Admin {
	w := &osadminv1.Admin{Name: a.Name, Uid: int32(min(a.UID, 1<<30)), Role: roleToWire(a.Role), Created: timestamppb.New(a.Created), CreatedBy: a.CreatedBy, CredentialsSet: a.HasCredentials()} // #nosec G115 -- clamped
	if a.Password != nil {
		w.PasswordChanged = timestamppb.New(a.Password.Changed)
	}
	if a.TOTP != nil {
		w.TotpAdded = timestamppb.New(a.TOTP.Added)
	}
	if a.Invite != nil {
		w.InviteExpires = timestamppb.New(a.Invite.Expires)
	}
	if a.LastSignIn != nil {
		w.LastSignIn = timestamppb.New(*a.LastSignIn)
	}
	for _, k := range a.Keys {
		w.Keys = append(w.Keys, keyToWire(k))
	}
	return w
}

func keyToWire(k access.AdminKey) *osadminv1.Key {
	w := &osadminv1.Key{Fingerprint: k.Fingerprint, Type: k.Type, Comment: k.Comment, Added: timestamppb.New(k.Added), AddedBy: k.AddedBy, Via: k.Via, Serial: k.Serial}
	if k.LastUsed != nil {
		w.LastUsed = timestamppb.New(*k.LastUsed)
	}
	if k.ValidBefore != nil {
		w.ValidBefore = timestamppb.New(*k.ValidBefore)
	}
	return w
}

// HostKeys are the SSH host keys' types and fingerprints, for the console.
func (s *Server) HostKeys() []*osadminv1.HostKey { return s.hostKeys() }

// hostKeys reads the SSH host public keys; a box before sshd's first start
// has none.
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
	name := r.Msg.GetName()
	c.note(name, "role", r.Msg.GetRole().String(), "rootOperator", strconv.FormatBool(r.Msg.GetRootOperator()))
	role, err := roleFromWire(r.Msg.GetRole())
	if err != nil {
		return nil, err
	}
	code, invite := h.s.newInvite()
	now := h.s.o.Clock.Now().UTC()
	var added access.Admin
	err = h.s.o.Access.Update(func(st *access.State) error {
		if _, taken := st.Admin(name); taken {
			return codes.New(codes.AccessName, "there is already an admin named %q", name)
		}
		a := st.AddAdmin(name, role, c.session.Admin, now)
		a.Invite = invite
		if r.Msg.GetRootOperator() {
			addToRoster(st, name)
		}
		added = *a
		return nil
	})
	if err != nil {
		return nil, err
	}
	h.s.o.Logger.Info("osadmin: admin added, invitation out", log.F("admin", added.Name), log.F("role", string(role)), log.F("by", c.session.Admin))
	return connect.NewResponse(&osadminv1.AddAdminResponse{Admin: adminToWire(added), Invitation: &osadminv1.Invitation{Admin: name, Code: code, Expires: timestamppb.New(invite.Expires)}}), nil
}

// addToRoster puts name on the root-operator roster, keeping its
// threshold.
func addToRoster(st *access.State, name string) {
	q := st.EffectiveQuorum()
	if slices.Contains(q.Members, name) {
		return
	}
	st.Quorum = &access.QuorumRoster{Members: append(slices.Clone(q.Members), name), Required: max(q.Required, min(2, len(q.Members)+1))}
}

// dropFromRoster takes name off the roster; the threshold shrinks with it.
func dropFromRoster(st *access.State, name string) {
	if st.Quorum == nil {
		return
	}
	m := slices.DeleteFunc(slices.Clone(st.Quorum.Members), func(x string) bool { return x == name })
	req := min(st.Quorum.Required, len(m))
	if len(m) >= 2 {
		req = max(req, 2)
	}
	st.Quorum = &access.QuorumRoster{Members: m, Required: req}
}

func (h *accessSvc) RemoveAdmin(ctx context.Context, r *connect.Request[osadminv1.RemoveAdminRequest]) (*connect.Response[osadminv1.RemoveAdminResponse], error) {
	c := callFrom(ctx)
	name := r.Msg.GetName()
	c.note(name)
	err := h.s.o.Access.UpdateAs(c.session.Admin, func(st *access.State) error {
		i := slices.IndexFunc(st.Admins, func(a access.Admin) bool { return a.Name == name })
		if i < 0 {
			return codes.New(codes.AccessName, "there is no admin named %q", name)
		}
		st.Admins = slices.Delete(st.Admins, i, i+1)
		dropFromRoster(st, name)
		return nil
	})
	if err != nil {
		return nil, err
	}
	h.s.o.Lockout.Forget(name)
	n := h.s.sessions.EndWhere(func(s weblogin.Session) bool { return s.Admin == name })
	e := h.s.endElevations(c.session.Admin, func(r elevation.Request) bool { return r.Admin == name })
	h.s.o.Logger.Info("osadmin: admin removed", log.F("admin", name), log.F("sessionsEnded", n), log.F("elevationsEnded", e), log.F("by", c.session.Admin))
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

func (h *accessSvc) RemoveKey(ctx context.Context, r *connect.Request[osadminv1.RemoveKeyRequest]) (*connect.Response[osadminv1.RemoveKeyResponse], error) {
	c := callFrom(ctx)
	admin, fp := r.Msg.GetAdmin(), r.Msg.GetFingerprint()
	c.note(admin, "key", fp)
	if err := mayManageKeys(c, admin); err != nil {
		return nil, err
	}
	err := h.s.o.Access.UpdateAs(c.session.Admin, func(st *access.State) error {
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
	e := h.s.endElevations(c.session.Admin, func(r elevation.Request) bool { return r.KeyFP == fp })
	h.s.o.Logger.Info("osadmin: key removed and revoked", log.F("admin", admin), log.F("key", fp), log.F("rootShellsEnded", e), log.F("by", c.session.Admin))
	return connect.NewResponse(&osadminv1.RemoveKeyResponse{}), nil
}

// endElevations ends the elevated shells, and revokes the unused
// certificates, of the requests match picks: those a removed key or admin
// signed in. It returns how many it ended.
func (s *Server) endElevations(by string, match func(elevation.Request) bool) int {
	if s.o.Elevation == nil {
		return 0
	}
	n := 0
	for _, r := range s.o.Elevation.List() {
		if (r.State != elevation.Active && r.State != elevation.Issued && r.State != elevation.Opened && r.State != elevation.Challenged) || !match(r) {
			continue
		}
		if _, err := s.o.Elevation.Terminate(r.ID, by); err != nil {
			s.o.Logger.Warn("osadmin: an elevation of a removed key didn't end", log.F("id", r.ID), log.F("error", describe(err)))
			continue
		}
		n++
	}
	return n
}

// UnrevokeKey takes a removed login key off the revocation list, so it can
// be added again.
func (h *accessSvc) UnrevokeKey(ctx context.Context, r *connect.Request[osadminv1.UnrevokeKeyRequest]) (*connect.Response[osadminv1.UnrevokeKeyResponse], error) {
	c := callFrom(ctx)
	fp := r.Msg.GetFingerprint()
	c.note("revoked login key", "key", fp)
	err := h.s.o.Access.Update(func(st *access.State) error {
		if !st.Unrevoke(fp) {
			return codes.New(codes.AccessKeyType, "key %s isn't revoked", fp)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	h.s.o.Logger.Info("osadmin: key un-revoked", log.F("key", fp), log.F("by", c.session.Admin))
	return connect.NewResponse(&osadminv1.UnrevokeKeyResponse{}), nil
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
