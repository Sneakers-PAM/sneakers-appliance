// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxsecrets"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/edgefall"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/rootrotate"
)

// rootRotateFile is the rotation's state, in the platform directory.
const rootRotateFile = "rootrotate.json"

// rootRotateWhat names the rotation to the maintenance gate.
const rootRotateWhat = "vault root key rotation"

// DefaultRootRotateBound is how long each wait of a rotation lasts: the
// vault's roll-out and its report of the move.
const DefaultRootRotateBound = 10 * time.Minute

// RootKeyStore is the box's secrets store as a rotation uses it
// (boxsecrets.Store on the box).
type RootKeyStore interface {
	Ensure(slot string) error
	BeginRotation(slot, name string) (boxsecrets.Rotation, error)
	EndRotation(slot, name string) error
	Rotating(slot string) (bool, error)
	Value(slot, name string) (string, bool, error)
}

// RootKeyStatus reads what the product's workload says about a key's move,
// from a pod that started at or after notBefore.
type RootKeyStatus interface {
	RootKeyStatus(ctx context.Context, ns, kind, name string, notBefore time.Time) (rootrotate.VaultStatus, error)
}

type rootKeySvc struct {
	osadminv1connect.UnimplementedRootKeyServiceHandler
	s *Server
}

// rotationEntry is the installed product's escrow key that can be rotated.
func (s *Server) rotationEntry() (productspec.EscrowKey, string, bool) {
	info, spec := s.installedSpec()
	if !info.Present() {
		return productspec.EscrowKey{}, "", false
	}
	for _, e := range spec.Escrow {
		if e.Previous != "" {
			return e, info.Name, true
		}
	}
	return productspec.EscrowKey{}, "", false
}

func (s *Server) rotateAvailable() bool {
	_, _, ok := s.rotationEntry()
	return ok && s.o.RootKeys != nil && s.o.RootKeyStatus != nil && s.o.TelemetryWorkloads != nil && s.o.KeyCustody != nil
}

func (s *Server) rootRotateRunner(env rootrotate.Env, e productspec.EscrowKey, product string) *rootrotate.Runner {
	poll, bound := s.o.RootRotatePoll, s.o.RootRotateBound
	if poll <= 0 {
		poll = 3 * time.Second
	}
	if bound <= 0 {
		bound = DefaultRootRotateBound
	}
	return &rootrotate.Runner{
		Env: env, StateFile: filepath.Join(s.o.Paths.State, "platform", rootRotateFile), Poll: poll, Bound: bound,
		Key: ProductEscrowName(product, e.Name), Staging: rootStagingName(product, e.Name),
	}
}

// rootStagingName is the sealed item that holds the new key while the vault
// moves to it.
func rootStagingName(product, key string) string { return ProductEscrowName(product, key+"-next") }

// rotationUnfinished reports a rotation begun and not finished, and not
// running now: anything that applies the product waits for it.
func (s *Server) rotationUnfinished() bool {
	if s.rootRotating.Load() {
		return false
	}
	e, product, ok := s.rotationEntry()
	if !ok {
		return false
	}
	_, _, active, err := s.rootRotateRunner(nil, e, product).Progress()
	// A previous key held with no state file is a rotation too: the store
	// switched keys and the vault hasn't moved.
	return (err == nil && active) || s.rotationHeld()
}

// rotationHeld reports whether the product's key is held with a previous
// key, so its sealed copy must not be replaced from the live Secret.
func (s *Server) rotationHeld() bool {
	if s.o.RootKeys == nil {
		return false
	}
	held, err := s.o.RootKeys.Rotating(s.slots().Current())
	return err == nil && held
}

func (h *rootKeySvc) GetRootKeyRotation(_ context.Context, _ *connect.Request[osadminv1.GetRootKeyRotationRequest]) (*connect.Response[osadminv1.GetRootKeyRotationResponse], error) {
	s := h.s
	res := &osadminv1.GetRootKeyRotationResponse{State: "none"}
	e, product, ok := s.rotationEntry()
	if !ok {
		return connect.NewResponse(res), nil
	}
	res.Available = s.rotateAvailable()
	step, why, active, err := s.rootRotateRunner(nil, e, product).Progress()
	switch {
	case err != nil:
		return nil, err
	case s.rootRotating.Load():
		res.State, res.Step = "running", step
	case active:
		res.State, res.Step, res.Why = "stopped", step, why
	case s.rotationHeld():
		res.State, res.Step, res.Why = "stopped", "begin", "the previous key is held and no step is recorded"
	case s.rootRotateDone.Load():
		res.State = "done"
	}
	return connect.NewResponse(res), nil
}

func (h *rootKeySvc) RotateRootKey(ctx context.Context, r *connect.Request[osadminv1.RotateRootKeyRequest]) (*connect.Response[osadminv1.RotateRootKeyResponse], error) {
	s, c := h.s, callFrom(ctx)
	e, product, ok := s.rotationEntry()
	if !ok || !s.rotateAvailable() {
		return nil, codes.New(codes.RootRotationUnavailable, "the installed product can't rotate its vault root key")
	}
	if len(s.o.Access.Read().RecoveryKeys) == 0 {
		return nil, codes.New(codes.SetupIncomplete, "there is no recovery key yet; add one first, so the escrow can carry the new key")
	}
	if !s.rootRotating.CompareAndSwap(false, true) {
		return nil, codes.New(codes.RootRotationUnfinished, "a root key rotation is running")
	}
	overrode, err := s.beginMaintenance(ctx, rootRotateWhat, edgefall.KindProductApply, c.by("product.rootkey.rotate"), r.Msg.GetElevationOverride())
	if err != nil {
		s.rootRotating.Store(false)
		return nil, err
	}
	if overrode != "" {
		c.note("root key", "overrode", overrode)
	}
	s.rootRotateDone.Store(false)
	env := &rotateEnv{s: s, entry: e, product: product}
	run := s.rootRotateRunner(env, e, product)
	env.bound = run.Bound
	s.holdMaintenance(8*run.Bound + time.Minute)
	s.o.Logger.Info("osadmin: the vault root key rotation begins", log.F("key", e.Name), log.F("by", c.session.Admin))
	go func() {
		defer s.rootRotating.Store(false)
		defer s.endMaintenance()
		// The rotation outlives the request that began it, so its context keeps the
		// request's values and drops its cancellation.
		if err := run.Run(context.WithoutCancel(ctx)); err != nil {
			code := "stopped"
			if errors.Is(err, rootrotate.ErrNotVerified) {
				code = codes.Describe(codes.New(codes.RootRotationNotVerified, "%s", err.Error()))
			}
			s.o.Logger.Error(err, "osadmin: the vault root key rotation stopped; both keys are kept and a new request carries on", log.F("key", e.Name), log.F("detail", code))
			return
		}
		s.rootRotateDone.Store(true)
		s.o.Logger.Info("osadmin: the vault root key rotation finished", log.F("key", e.Name))
	}()
	return connect.NewResponse(&osadminv1.RotateRootKeyResponse{}), nil
}

// rotateEnv is the box as a rotation works on it.
type rotateEnv struct {
	s       *Server
	entry   productspec.EscrowKey
	product string
	// bound is how long the vault may take to roll out after a restart.
	bound time.Duration
}

func (v *rotateEnv) slot() string { return v.s.slots().Current() }

func (v *rotateEnv) Begin(context.Context) (rootrotate.Keys, error) {
	r, err := v.s.o.RootKeys.BeginRotation(v.slot(), v.entry.Name)
	return rootrotate.Keys{Current: r.Current, Previous: r.Previous}, err
}

func (v *rotateEnv) seal(ctx context.Context, name string, key []byte) error {
	_, err := v.s.o.KeyCustody.Seal(ctx, connect.NewRequest(&initv1.SealRequest{Name: name, Secret: key}))
	return err
}

func (v *rotateEnv) SealStaging(ctx context.Context, key []byte) error {
	return v.seal(ctx, rootStagingName(v.product, v.entry.Name), key)
}

// RefreshEscrow writes a new escrow to the recovery keys whether or not a
// sealed item changed: what it carries is what is sealed now.
func (v *rotateEnv) RefreshEscrow(ctx context.Context) error {
	if _, err := v.s.sealProductKeys(ctx); err != nil {
		return err
	}
	if len(v.s.o.Access.Read().RecoveryKeys) == 0 {
		return codes.New(codes.SetupIncomplete, "there is no recovery key yet; add one first")
	}
	return v.s.changeRecoveryKeys(ctx, func(*access.State) error { return nil })
}

func (v *rotateEnv) Apply(ctx context.Context) error {
	if err := v.s.o.RootKeys.Ensure(v.slot()); err != nil {
		return err
	}
	return v.s.o.TelemetryWorkloads.Applied(ctx)
}

// Restart restarts the workloads that read the key and waits for each to
// roll out; it returns the time just before the first restart, which every
// new pod starts after.
func (v *rotateEnv) Restart(ctx context.Context) (time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, v.bound)
	defer cancel()
	w := v.s.o.TelemetryWorkloads
	at := v.s.o.Clock.Now()
	for _, ref := range v.entry.Restart {
		ns, kind, name, _ := productspec.SplitRestart(ref)
		if err := w.Restart(ctx, ns, kind, name); err != nil {
			return time.Time{}, err
		}
	}
	for _, ref := range v.entry.Restart {
		ns, kind, name, _ := productspec.SplitRestart(ref)
		for {
			why, present, err := w.RolledOut(ctx, ns, kind, name)
			if err == nil && present && why == "" {
				break
			}
			select {
			case <-ctx.Done():
				return time.Time{}, fmt.Errorf("%s isn't back: %w", ref, ctx.Err())
			case <-time.After(v.s.rolloutPoll()):
			}
		}
	}
	return at, nil
}

func (v *rotateEnv) Status(ctx context.Context, notBefore time.Time) (rootrotate.VaultStatus, error) {
	ns, kind, name, _ := productspec.SplitRestart(v.entry.Restart[0])
	return v.s.o.RootKeyStatus.RootKeyStatus(ctx, ns, kind, name, notBefore)
}

func (v *rotateEnv) End(context.Context) error {
	return v.s.o.RootKeys.EndRotation(v.slot(), v.entry.Name)
}

func (v *rotateEnv) CurrentKey(context.Context) ([]byte, error) {
	val, found, err := v.s.o.RootKeys.Value(v.slot(), v.entry.Name)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("the box holds no value for %s", v.entry.Name)
	}
	return []byte(val), nil
}

func (v *rotateEnv) SealCanonical(ctx context.Context, key []byte) error {
	return v.seal(ctx, ProductEscrowName(v.product, v.entry.Name), key)
}

func (v *rotateEnv) RetireStaging(ctx context.Context) error {
	_, err := v.s.o.KeyCustody.Retire(ctx, connect.NewRequest(&initv1.RetireRequest{Name: rootStagingName(v.product, v.entry.Name)}))
	return err
}

// Audit records an event with item names only, never a value.
func (v *rotateEnv) Audit(event string, names ...string) {
	d := map[string]string{"event": event}
	for i, n := range names {
		d[fmt.Sprintf("item%d", i+1)] = n
	}
	v.s.write(osaudit.Entry{Actor: "box", Action: "product.rootkey.rotation", Target: v.entry.Name, Detail: d}, nil)
}

// rolloutPoll is how often a restarted workload is asked whether it is back.
func (s *Server) rolloutPoll() time.Duration {
	if s.o.RootRotatePoll > 0 {
		return s.o.RootRotatePoll
	}
	return time.Second
}
