// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/credentials"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/ppk"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/weblogin"
)

// IssueSshKey makes the caller an ed25519 key pair, signs it with the root
// key as an SSH user certificate, keeps the public half and the
// certificate, and returns the private key this once.
func (h *accessSvc) IssueSshKey(ctx context.Context, r *connect.Request[osadminv1.IssueSshKeyRequest]) (*connect.Response[osadminv1.IssueSshKeyResponse], error) {
	c := callFrom(ctx)
	admin := c.session.Admin
	st := h.s.o.Access.Read()
	days := int(r.Msg.GetValidDays())
	if days == 0 {
		days = st.AccessPolicy.Effective().SSHKeyValidDays
	}
	if days < access.MinKeyValidDays || days > access.MaxKeyValidDays {
		return nil, codes.New(codes.AccessPolicy, "an SSH key is valid for %d to %d days", access.MinKeyValidDays, access.MaxKeyValidDays)
	}
	label := strings.TrimSpace(r.Msg.GetLabel())
	if len(label) > 64 || strings.ContainsAny(label, "\r\n") {
		return nil, codes.New(codes.AccessName, "a key's label is one line of at most 64 characters")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ssh key: %w", err)
	}
	spk, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("ssh key: %w", err)
	}
	now := h.s.o.Clock.Now().UTC()
	vb := now.Add(time.Duration(days) * 24 * time.Hour)
	var issued access.AdminKey
	var certLine string
	err = h.s.o.Access.Update(func(st *access.State) error {
		a, ok := st.Admin(admin)
		if !ok {
			return codes.New(codes.AccessName, "there is no admin named %q", admin)
		}
		serial := max(st.NextSerial, 1)
		st.NextSerial = serial + 1
		cert, err := h.s.o.RootKey.IssueUserCert(spk, admin, serial, now.Add(-time.Minute), vb)
		if err != nil {
			return err
		}
		certLine = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
		k, err := access.ParseLoginKey(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(spk))) + " " + label)
		if err != nil {
			return err
		}
		k.Comment = label
		issued = access.AdminKey{Key: k, Added: now, AddedBy: admin, Via: access.ViaIssued, Serial: serial, ValidBefore: &vb, Certificate: certLine}
		a.Keys = append(a.Keys, issued)
		return nil
	})
	if err != nil {
		return nil, err
	}
	comment := admin + "@sneakers-appliance " + label
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, fmt.Errorf("ssh key: %w", err)
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certLine))
	if err != nil {
		return nil, fmt.Errorf("ssh key: %w", err)
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("ssh key: the issued certificate isn't a certificate")
	}
	putty, err := ppk.Marshal(priv, cert, strings.TrimSpace(comment))
	if err != nil {
		return nil, fmt.Errorf("ssh key: %w", err)
	}
	file := keyFileName(admin, issued.Serial)
	c.note(admin, "key", issued.Fingerprint, "serial", strconv.FormatUint(issued.Serial, 10), "validBefore", vb.Format(time.RFC3339))
	h.s.o.Logger.Info("osadmin: SSH key issued", log.F("admin", admin), log.F("key", issued.Fingerprint), log.F("serial", issued.Serial), log.F("file", file))
	return connect.NewResponse(&osadminv1.IssueSshKeyResponse{
		Key: keyToWire(issued), PrivateKey: string(pem.EncodeToMemory(block)), Certificate: certLine,
		PublicKey: issued.PublicKey, FileName: file, CertificateFileName: file + "-cert.pub",
		Ppk: string(putty), PpkFileName: file + ".ppk",
		SshCommand: sshCommand(file, admin, h.s.boxHost(ctx)),
	}), nil
}

// keyFileName names an issued key's files by its admin and serial, so no
// two keys share a name and a browser never renames a repeated download.
func keyFileName(admin string, serial uint64) string {
	return "id_ed25519_" + admin + "_sneakers_" + strconv.FormatUint(serial, 10)
}

// sshCommand is the OpenSSH login for an issued key; host is the box's
// name or address, or a placeholder when netd doesn't say.
func sshCommand(file, admin, host string) string {
	if host == "" {
		host = "<this box>"
	}
	return "ssh -i " + file + " -o CertificateFile=" + file + "-cert.pub " + admin + "@" + strings.Trim(host, "[]")
}

func (h *accessSvc) ChangePassword(ctx context.Context, r *connect.Request[osadminv1.ChangePasswordRequest]) (*connect.Response[osadminv1.ChangePasswordResponse], error) {
	c := callFrom(ctx)
	admin := c.session.Admin
	c.note(admin)
	st := h.s.o.Access.Read()
	a, ok := st.Admin(admin)
	if !ok || !a.HasCredentials() {
		return nil, codes.New(codes.AccessSession, "sign in again")
	}
	if err := h.s.o.Lockout.Check(admin, c.source, h.s.o.Clock.Now()); err != nil {
		return nil, err
	}
	if !credentials.VerifyPassword(h.s.o.RootKey.Pepper(), a.Password.Hash, r.Msg.GetCurrentPassword()) {
		return nil, h.s.failed(admin, c.source, osaudit.SurfaceAdmin, "the current password is wrong")
	}
	if err := credentials.CheckPassword(r.Msg.GetNewPassword(), admin); err != nil {
		return nil, err
	}
	hash, err := credentials.HashPassword(h.s.o.RootKey.Pepper(), r.Msg.GetNewPassword())
	if err != nil {
		return nil, err
	}
	now := h.s.o.Clock.Now().UTC()
	if err := h.s.o.Access.Update(func(st *access.State) error {
		x, ok := st.Admin(admin)
		if !ok {
			return codes.New(codes.AccessName, "there is no admin named %q", admin)
		}
		x.Password = &access.Password{Hash: hash, Changed: now}
		return nil
	}); err != nil {
		return nil, err
	}
	n := h.s.sessions.EndWhere(func(x weblogin.Session) bool { return x.Admin == admin && x.ID != c.session.ID })
	h.s.o.Logger.Info("osadmin: password changed", log.F("admin", admin), log.F("otherSessionsEnded", n))
	return connect.NewResponse(&osadminv1.ChangePasswordResponse{}), nil
}

func (h *accessSvc) BeginTotpReplacement(ctx context.Context, _ *connect.Request[osadminv1.BeginTotpReplacementRequest]) (*connect.Response[osadminv1.BeginTotpReplacementResponse], error) {
	c := callFrom(ctx)
	c.note(c.session.Admin)
	en, err := h.s.creds.startEnrolment(c.session.Admin, "", "", c.session.ID, h.s.o.Clock.Now())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.BeginTotpReplacementResponse{Totp: h.s.totpToWire(en)}), nil
}

func (h *accessSvc) CompleteTotpReplacement(ctx context.Context, r *connect.Request[osadminv1.CompleteTotpReplacementRequest]) (*connect.Response[osadminv1.CompleteTotpReplacementResponse], error) {
	c := callFrom(ctx)
	admin := c.session.Admin
	c.note(admin)
	now := h.s.o.Clock.Now()
	en, ok := h.s.creds.enrolmentOf(r.Msg.GetEnrolmentId(), now)
	if !ok || !en.Replaces || en.Admin != admin || en.Session != c.session.ID {
		return nil, codes.New(codes.SetupIncomplete, "that authenticator setup has expired; start again")
	}
	step, err := checkNewTOTP(en, r.Msg.GetTotpCode(), now)
	if err != nil {
		return nil, h.s.failed(admin, c.source, osaudit.SurfaceAdmin, codes.Describe(err))
	}
	sealed, err := credentials.SealTOTP(h.s.o.RootKey.Pepper(), admin, en.Secret)
	if err != nil {
		return nil, err
	}
	if err := h.s.o.Access.Update(func(st *access.State) error {
		x, ok := st.Admin(admin)
		if !ok {
			return codes.New(codes.AccessName, "there is no admin named %q", admin)
		}
		x.TOTP = &access.TOTP{Sealed: sealed, Added: now.UTC()}
		return nil
	}); err != nil {
		return nil, err
	}
	h.s.creds.drop(en.ID)
	h.s.o.Lockout.SetStep(admin, step)
	h.s.o.Logger.Info("osadmin: authenticator replaced", log.F("admin", admin))
	return connect.NewResponse(&osadminv1.CompleteTotpReplacementResponse{}), nil
}

func (h *accessSvc) ReinviteAdmin(ctx context.Context, r *connect.Request[osadminv1.ReinviteAdminRequest]) (*connect.Response[osadminv1.ReinviteAdminResponse], error) {
	c := callFrom(ctx)
	name := r.Msg.GetName()
	c.note(name)
	if name == c.session.Admin {
		return nil, codes.New(codes.AccessForbidden, "an owner doesn't re-invite themselves; change the password or the authenticator instead")
	}
	code, invite := h.s.newInvite()
	if err := h.s.o.Access.UpdateAs(c.session.Admin, func(st *access.State) error {
		a, ok := st.Admin(name)
		if !ok {
			return codes.New(codes.AccessName, "there is no admin named %q", name)
		}
		a.Password, a.TOTP, a.Invite = nil, nil, invite
		return nil
	}); err != nil {
		return nil, err
	}
	h.s.o.Lockout.Forget(name)
	n := h.s.sessions.EndWhere(func(x weblogin.Session) bool { return x.Admin == name })
	h.s.o.Logger.Info("osadmin: admin re-invited", log.F("admin", name), log.F("sessionsEnded", n), log.F("by", c.session.Admin))
	return connect.NewResponse(&osadminv1.ReinviteAdminResponse{Invitation: &osadminv1.Invitation{Admin: name, Code: code, Expires: timestamppb.New(invite.Expires)}}), nil
}

func (h *accessSvc) UnlockAdmin(ctx context.Context, r *connect.Request[osadminv1.UnlockAdminRequest]) (*connect.Response[osadminv1.UnlockAdminResponse], error) {
	c := callFrom(ctx)
	name := r.Msg.GetName()
	st := h.s.o.Access.Read()
	if _, ok := st.Admin(name); !ok {
		c.note(name)
		return nil, codes.New(codes.AccessName, "there is no admin named %q", name)
	}
	was := h.s.o.Lockout.Unlock(name)
	c.note(name, "wasLocked", strconv.FormatBool(was))
	h.s.o.Logger.Info("osadmin: admin unlocked", log.F("admin", name), log.F("wasLocked", was), log.F("by", c.session.Admin))
	return connect.NewResponse(&osadminv1.UnlockAdminResponse{}), nil
}

func (h *accessSvc) SetAccessPolicy(ctx context.Context, r *connect.Request[osadminv1.SetAccessPolicyRequest]) (*connect.Response[osadminv1.SetAccessPolicyResponse], error) {
	c := callFrom(ctx)
	w := r.Msg.GetPolicy()
	p := access.Policy{RootCodeMinutes: int(w.GetRootCodeMinutes()), RootSessionMinutes: int(w.GetRootSessionMinutes()), SSHKeyValidDays: int(w.GetSshKeyValidDays())}
	switch w.GetLockoutMode() {
	case osadminv1.LockoutMode_LOCKOUT_MODE_TIMED:
		p.LockoutMode = access.LockoutTimed
	case osadminv1.LockoutMode_LOCKOUT_MODE_UNTIL_UNLOCKED:
		p.LockoutMode = access.LockoutUntilUnlocked
	default:
		return nil, codes.New(codes.AccessPolicy, "choose a lockout mode")
	}
	c.note("access-policy", "lockoutMode", p.LockoutMode, "rootCodeMinutes", itoa(p.RootCodeMinutes), "rootSessionMinutes", itoa(p.RootSessionMinutes), "sshKeyValidDays", itoa(p.SSHKeyValidDays))
	if p.RootCodeMinutes == 0 || p.RootSessionMinutes == 0 || p.SSHKeyValidDays == 0 {
		return nil, codes.New(codes.AccessPolicy, "give every setting: the root-shell code and session lifetimes and the SSH key validity")
	}
	if err := h.s.o.Access.Update(func(st *access.State) error {
		st.AccessPolicy = p
		return nil
	}); err != nil {
		return nil, err
	}
	h.s.o.Logger.Info("osadmin: access policy set", log.F("by", c.session.Admin))
	return connect.NewResponse(&osadminv1.SetAccessPolicyResponse{}), nil
}

func policyToWireAccess(p access.Policy) *osadminv1.AccessPolicy {
	mode := osadminv1.LockoutMode_LOCKOUT_MODE_TIMED
	if p.LockoutMode == access.LockoutUntilUnlocked {
		mode = osadminv1.LockoutMode_LOCKOUT_MODE_UNTIL_UNLOCKED
	}
	return &osadminv1.AccessPolicy{
		LockoutMode: mode, RootCodeMinutes: int32(min(p.RootCodeMinutes, 1<<30)), RootSessionMinutes: int32(min(p.RootSessionMinutes, 1<<30)), // #nosec G115 -- clamped
		SshKeyValidDays: int32(min(p.SSHKeyValidDays, 1<<30)), // #nosec G115 -- clamped
	}
}
