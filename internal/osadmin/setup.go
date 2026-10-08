// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netdapi"
)

// The setup markers in Paths.SetupDir.
const (
	// DoneMarker is spec 1's completion marker; init enters normal on the
	// next boot once it exists.
	DoneMarker = "done"
	// SingleAdminMarker records that the operator confirmed the
	// single-admin warning.
	SingleAdminMarker = "single-admin-acknowledged"
	// SignedInMarker records the first :8443 sign-in, first boot's step 5.
	SignedInMarker = "signed-in"
)

type setup struct {
	osadminv1connect.UnimplementedSetupServiceHandler
	s *Server
}

// SetupDone reports whether setup has finished; the access store applies the
// recovery-key invariant only then.
func (s *Server) SetupDone() bool { return exists(filepath.Join(s.o.Paths.SetupDir(), DoneMarker)) }

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func (h *setup) GetSetup(ctx context.Context, _ *connect.Request[osadminv1.GetSetupRequest]) (*connect.Response[osadminv1.GetSetupResponse], error) {
	c := callFrom(ctx)
	st := h.s.o.Access.Read()
	steps := h.s.setupSteps()
	cur, _ := currentStep(steps)
	if c.code != nil {
		// Before an admin exists, the code session sees the steps only.
		out := &osadminv1.GetSetupResponse{Done: h.s.SetupDone(), Steps: steps, Current: cur, CodeKind: c.code.Kind, CodeAdmin: c.code.Admin,
			CodeSessionExpires: timestamppb.New(c.code.Expires), MaxRecoveryKeys: access.MaxRecoveryKeys}
		return connect.NewResponse(out), nil
	}
	out := &osadminv1.GetSetupResponse{
		Steps:                   steps,
		Current:                 cur,
		Done:                    h.s.SetupDone(),
		MaxRecoveryKeys:         access.MaxRecoveryKeys,
		AdminCount:              int32(min(len(st.Admins), 1<<30)), // #nosec G115 -- clamped
		SingleAdminWarning:      len(st.Admins) == 1,
		SingleAdminAcknowledged: exists(filepath.Join(h.s.o.Paths.SetupDir(), SingleAdminMarker)),
		SignedIn:                exists(filepath.Join(h.s.o.Paths.SetupDir(), SignedInMarker)),
		ProductSetupUrl:         h.s.productSetupURL(ctx),
	}
	for _, r := range st.RecoveryKeys {
		out.RecoveryKeys = append(out.RecoveryKeys, recoveryToWire(r))
	}
	if name, _ := h.s.newestEscrow(); name != "" {
		out.EscrowFile = name
	}
	for _, a := range st.Admins {
		if a.CreatedBy == "setup" {
			out.FirstAdmin = a.Name
		}
	}
	return connect.NewResponse(out), nil
}

func recoveryToWire(r access.RecoveryKey) *osadminv1.RecoveryKey {
	return &osadminv1.RecoveryKey{Fingerprint: r.Fingerprint, Type: r.Type, Label: r.Label, Set: timestamppb.New(r.Set), SetBy: r.SetBy}
}

func (h *setup) AddRecoveryKey(ctx context.Context, r *connect.Request[osadminv1.AddRecoveryKeyRequest]) (*connect.Response[osadminv1.AddRecoveryKeyResponse], error) {
	c := callFrom(ctx)
	k, err := access.ParseRecoveryKey(r.Msg.GetPublicKey())
	if err != nil {
		return nil, err
	}
	c.note(k.Fingerprint)
	rk, err := h.s.addRecoveryKey(ctx, k, strings.TrimSpace(r.Msg.GetLabel()), c.session.Admin)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.AddRecoveryKeyResponse{RecoveryKey: recoveryToWire(rk)}), nil
}

// GenerateRecoveryKey makes an ed25519 key pair, adds its public half as a
// recovery key exactly as AddRecoveryKey does, and returns the private key
// this once. It never reaches the store, the audit entry or the log.
func (h *setup) GenerateRecoveryKey(ctx context.Context, r *connect.Request[osadminv1.GenerateRecoveryKeyRequest]) (*connect.Response[osadminv1.GenerateRecoveryKeyResponse], error) {
	c := callFrom(ctx)
	label := strings.TrimSpace(r.Msg.GetLabel())
	if len(label) > 64 || strings.ContainsAny(label, "\r\n") {
		return nil, codes.New(codes.AccessName, "a key's label is one line of at most 64 characters")
	}
	if n := len(h.s.o.Access.Read().RecoveryKeys); n >= access.MaxRecoveryKeys {
		return nil, recoveryKeyLimit()
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("recovery key: %w", err)
	}
	spk, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("recovery key: %w", err)
	}
	k, err := access.ParseRecoveryKey(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(spk))))
	if err != nil {
		return nil, err
	}
	c.note(k.Fingerprint)
	rk, err := h.s.addRecoveryKey(ctx, k, label, c.session.Admin)
	if err != nil {
		return nil, err
	}
	comment := "sneakers-appliance recovery key"
	if label != "" {
		comment += " " + label
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, fmt.Errorf("recovery key: %w", err)
	}
	h.s.o.Logger.Info("osadmin: recovery key generated on the box", log.F("admin", c.session.Admin), log.F("key", rk.Fingerprint))
	return connect.NewResponse(&osadminv1.GenerateRecoveryKeyResponse{
		RecoveryKey: recoveryToWire(rk),
		PrivateKey:  string(pem.EncodeToMemory(block)),
		PublicKey:   rk.PublicKey,
		FileName:    "sneakers-recovery-" + rk.Set.Format("20060102T150405Z"),
	}), nil
}

func recoveryKeyLimit() error {
	return codes.New(codes.AccessRecoveryKeyLimit, "a box holds at most %d recovery keys; remove one first", access.MaxRecoveryKeys)
}

// addRecoveryKey stores k as a recovery key set by admin and writes a new
// escrow to the whole set (changeRecoveryKeys).
func (s *Server) addRecoveryKey(ctx context.Context, k access.Key, label, admin string) (access.RecoveryKey, error) {
	rk := access.RecoveryKey{Key: k, Label: label, Set: s.o.Clock.Now().UTC(), SetBy: admin}
	err := s.changeRecoveryKeys(ctx, func(st *access.State) error {
		if len(st.RecoveryKeys) >= access.MaxRecoveryKeys {
			return recoveryKeyLimit()
		}
		st.RecoveryKeys = append(st.RecoveryKeys, rk)
		return nil
	})
	return rk, err
}

func (h *setup) RemoveRecoveryKey(ctx context.Context, r *connect.Request[osadminv1.RemoveRecoveryKeyRequest]) (*connect.Response[osadminv1.RemoveRecoveryKeyResponse], error) {
	c := callFrom(ctx)
	fp := r.Msg.GetFingerprint()
	c.note(fp)
	if err := h.s.changeRecoveryKeys(ctx, func(st *access.State) error {
		i := slices.IndexFunc(st.RecoveryKeys, func(k access.RecoveryKey) bool { return k.Fingerprint == fp })
		if i < 0 {
			return codes.New(codes.AccessKeyType, "there is no recovery key %s", fp)
		}
		if len(st.RecoveryKeys) == 1 {
			return codes.New(codes.AccessLastRecoveryKey, "the last recovery key can't be removed; add its replacement first")
		}
		st.RecoveryKeys = slices.Delete(st.RecoveryKeys, i, i+1)
		return nil
	}); err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.RemoveRecoveryKeyResponse{}), nil
}

// changeRecoveryKeys applies change, asks init for an escrow encrypted to
// the new set, stores the set and writes the escrow file. The escrow is
// made before the store changes, so a failed escrow changes nothing.
func (s *Server) changeRecoveryKeys(ctx context.Context, change func(*access.State) error) error {
	next := s.o.Access.Read()
	if err := change(&next); err != nil {
		return err
	}
	var recipients []string
	for _, r := range next.RecoveryKeys {
		recipients = append(recipients, r.PublicKey)
	}
	esc, err := s.o.KeyCustody.Escrow(ctx, connect.NewRequest(&initv1.EscrowRequest{Recipients: recipients}))
	if err != nil {
		s.o.Logger.Error(err, "osadmin: escrow failed; the recovery keys are unchanged")
		return err
	}
	if err := s.o.Access.Update(change); err != nil {
		return err
	}
	name, err := s.writeEscrow(esc.Msg.GetBundle())
	if err != nil {
		return err
	}
	s.o.Logger.Info("osadmin: recovery keys changed, new escrow written", log.F("recoveryKeys", len(recipients)), log.F("escrow", name))
	return nil
}

func (s *Server) writeEscrow(bundle []byte) (string, error) {
	dir := s.o.Paths.EscrowDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("escrow: %w", err)
	}
	name := "escrow-" + s.o.Clock.Now().UTC().Format("20060102T150405Z") + ".age"
	if err := writeAtomic(filepath.Join(dir, name), bundle); err != nil {
		return "", err
	}
	return name, nil
}

func (s *Server) newestEscrow() (string, error) {
	paths, err := filepath.Glob(filepath.Join(s.o.Paths.EscrowDir(), "escrow-*.age"))
	if err != nil || len(paths) == 0 {
		return "", err
	}
	sort.Strings(paths)
	return filepath.Base(paths[len(paths)-1]), nil
}

func (h *setup) DownloadEscrow(ctx context.Context, _ *connect.Request[osadminv1.DownloadEscrowRequest]) (*connect.Response[osadminv1.DownloadEscrowResponse], error) {
	name, err := h.s.newestEscrow()
	if err != nil {
		return nil, err
	}
	if name == "" {
		return nil, codes.New(codes.SetupIncomplete, "there is no escrow yet; add a recovery key first")
	}
	callFrom(ctx).note(name)
	b, err := os.ReadFile(filepath.Join(h.s.o.Paths.EscrowDir(), name)) // #nosec G304 -- the newest escrow file under the state volume
	if err != nil {
		return nil, fmt.Errorf("escrow: %w", err)
	}
	return connect.NewResponse(&osadminv1.DownloadEscrowResponse{FileName: name, Content: b}), nil
}

func (h *setup) AcknowledgeSingleAdmin(context.Context, *connect.Request[osadminv1.AcknowledgeSingleAdminRequest]) (*connect.Response[osadminv1.AcknowledgeSingleAdminResponse], error) {
	if err := h.s.mark(SingleAdminMarker); err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.AcknowledgeSingleAdminResponse{}), nil
}

func (h *setup) Finish(ctx context.Context, _ *connect.Request[osadminv1.FinishRequest]) (*connect.Response[osadminv1.FinishResponse], error) {
	st := h.s.o.Access.Read()
	if err := access.Check(st, true, true); err != nil {
		return nil, codes.New(codes.SetupIncomplete, "a step is still open: %s", codes.Describe(err))
	}
	if name, err := h.s.newestEscrow(); err != nil || name == "" {
		return nil, codes.New(codes.SetupIncomplete, "a step is still open: the escrow hasn't been written")
	}
	if len(st.Admins) == 1 && !exists(filepath.Join(h.s.o.Paths.SetupDir(), SingleAdminMarker)) {
		return nil, codes.New(codes.SetupIncomplete, "a step is still open: confirm the single-admin warning, or add a second admin")
	}
	for _, m := range []struct{ marker, step string }{{NetworkSeenMarker, "step 4, the network"}, {ProtectionSeenMarker, "step 5, the protection"}} {
		if !exists(filepath.Join(h.s.o.Paths.SetupDir(), m.marker)) {
			return nil, codes.New(codes.SetupIncomplete, "a step is still open: %s", m.step)
		}
	}
	if !exists(filepath.Join(h.s.o.Paths.SetupDir(), SignedInMarker)) {
		return nil, codes.New(codes.SetupIncomplete, "a step is still open: sign in once with your name, password and authenticator code")
	}
	if err := h.s.mark(DoneMarker); err != nil {
		return nil, err
	}
	h.s.consoleChanged()
	h.s.o.Logger.Info("osadmin: setup finished", log.F("by", callFrom(ctx).session.Admin))
	return connect.NewResponse(&osadminv1.FinishResponse{ProductSetupUrl: h.s.productSetupURL(ctx)}), nil
}

func (s *Server) mark(name string) error {
	dir := s.o.Paths.SetupDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("setup: %w", err)
	}
	return writeAtomic(filepath.Join(dir, name), nil)
}

// productSetupURL is the product's own first-run page, on the box's host
// name, or its first management address that isn't link-local.
func (s *Server) productSetupURL(ctx context.Context) string {
	st, err := s.o.Network.Status(ctx, connect.NewRequest(&netdv1.StatusRequest{}))
	if err != nil {
		return ""
	}
	host := st.Msg.GetHostname()
	if a := netdapi.Bindable(st.Msg.GetManagementAddresses()); host == "" && len(a) > 0 {
		host = a[0].String()
		if a[0].Is6() {
			host = "[" + host + "]"
		}
	}
	if host == "" {
		return ""
	}
	return "https://" + host + "/setup"
}

// writeAtomic writes b through a tmp file, fsyncs it and renames it into
// place.
func writeAtomic(p string, b []byte) error {
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- a path under the state volume
	if err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(p), err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", filepath.Base(p), err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", filepath.Base(p), err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(p), err)
	}
	if err := os.Rename(tmp, p); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(p), err)
	}
	return nil
}
