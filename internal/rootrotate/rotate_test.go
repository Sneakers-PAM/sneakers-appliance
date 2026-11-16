// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package rootrotate_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/rootrotate"
)

var errCrash = errors.New("the process died")

// fake is the box and the vault in memory. It enforces the order the rotation
// exists for: the previous key is dropped, the canonical sealed item is
// replaced and the staging copy is retired only after the vault has said
// verified, and a key is never made twice.
type fake struct {
	t *testing.T
	// the box secrets store
	current, previous string
	made              int
	// the sealed items
	canonical, staging string
	retired            []string
	escrows            []string // what each escrow carried: "canonical/staging"
	// the vault
	appliedWithPrevious bool
	restartedAt         time.Time
	verified            bool // the vault reported verified since its last start
	vaultState          string
	// calls and the crash plan
	calls   []string
	crashAt int // crash on this call number (1-based); 0 never
	n       int
	audits  []string
	clock   time.Time
}

func newFake(t *testing.T) *fake {
	return &fake{t: t, current: "key-old", canonical: "key-old", vaultState: "none", clock: time.Unix(1000, 0)}
}

func (f *fake) step(name string) error {
	f.n++
	f.calls = append(f.calls, name)
	if f.crashAt != 0 && f.n == f.crashAt {
		return errCrash
	}
	return nil
}

func (f *fake) Begin(context.Context) (rootrotate.Keys, error) {
	if err := f.step("begin"); err != nil {
		return rootrotate.Keys{}, err
	}
	if f.previous != "" {
		return rootrotate.Keys{Current: f.current, Previous: f.previous}, nil
	}
	f.made++
	f.previous, f.current = f.current, "key-new"
	return rootrotate.Keys{Current: f.current, Previous: f.previous}, nil
}

func (f *fake) SealStaging(_ context.Context, key []byte) error {
	if err := f.step("seal-staging"); err != nil {
		return err
	}
	f.staging = string(key)
	return nil
}

func (f *fake) RefreshEscrow(context.Context) error {
	if err := f.step("escrow"); err != nil {
		return err
	}
	f.escrows = append(f.escrows, f.canonical+"/"+f.staging)
	return nil
}

func (f *fake) Apply(context.Context) error {
	if err := f.step("apply"); err != nil {
		return err
	}
	f.appliedWithPrevious = f.previous != ""
	return nil
}

func (f *fake) Restart(context.Context) (time.Time, error) {
	if err := f.step("restart"); err != nil {
		return time.Time{}, err
	}
	f.clock = f.clock.Add(time.Minute)
	f.restartedAt = f.clock
	f.verified = false
	return f.restartedAt, nil
}

// Status is what the vault says, from a pod started at or after notBefore.
func (f *fake) Status(_ context.Context, notBefore time.Time) (rootrotate.VaultStatus, error) {
	if err := f.step("status"); err != nil {
		return rootrotate.VaultStatus{}, err
	}
	if f.restartedAt.Before(notBefore) {
		return rootrotate.VaultStatus{}, errors.New("no vault pod has started since")
	}
	switch {
	case f.vaultState == "failing":
		return rootrotate.VaultStatus{State: rootrotate.StateFailed, Pending: 2}, nil
	case f.appliedWithPrevious:
		f.verified = true
		return rootrotate.VaultStatus{State: rootrotate.StateVerified}, nil
	default:
		return rootrotate.VaultStatus{State: rootrotate.StateNone}, nil
	}
}

func (f *fake) End(context.Context) error {
	if err := f.step("end"); err != nil {
		return err
	}
	if !f.verified && f.previous != "" {
		f.t.Fatal("the previous key was dropped before the vault said verified")
	}
	f.previous = ""
	return nil
}

func (f *fake) CurrentKey(context.Context) ([]byte, error) {
	if err := f.step("current"); err != nil {
		return nil, err
	}
	return []byte(f.current), nil
}

func (f *fake) SealCanonical(_ context.Context, key []byte) error {
	if err := f.step("seal-canonical"); err != nil {
		return err
	}
	if f.previous != "" {
		f.t.Fatal("the canonical item was replaced while the previous key is still held")
	}
	f.canonical = string(key)
	return nil
}

func (f *fake) RetireStaging(context.Context) error {
	if err := f.step("retire"); err != nil {
		return err
	}
	if f.canonical != f.current {
		f.t.Fatal("the staging copy was retired before the canonical item holds the new key")
	}
	f.retired = append(f.retired, "staging")
	f.staging = ""
	return nil
}

func (f *fake) Audit(event string, names ...string) {
	f.audits = append(f.audits, event+" "+strings.Join(names, ","))
}

func runner(f *fake, dir string) *rootrotate.Runner {
	return &rootrotate.Runner{Env: f, StateFile: filepath.Join(dir, "rotate.json"), Poll: time.Millisecond, Bound: 50 * time.Millisecond, Key: "vault-root-key", Staging: "product-sneakers-vault-root-key-next"}
}

func done(t *testing.T, f *fake, dir string) {
	t.Helper()
	if f.current != "key-new" || f.canonical != "key-new" || f.previous != "" || f.staging != "" {
		t.Fatalf("not finished: current=%s canonical=%s previous=%q staging=%q", f.current, f.canonical, f.previous, f.staging)
	}
	if f.made != 1 {
		t.Fatalf("%d keys were made, want 1", f.made)
	}
	last := f.escrows[len(f.escrows)-1]
	if last != "key-new/" {
		t.Fatalf("the final escrow carried %q, want only the new key", last)
	}
	if _, err := os.Stat(filepath.Join(dir, "rotate.json")); !os.IsNotExist(err) {
		t.Fatalf("the state file is still there: %v", err)
	}
}

// The whole rotation, in order, with only names in the audit.
func TestARotationRunsEveryStepInOrder(t *testing.T) {
	f, dir := newFake(t), t.TempDir()
	if err := runner(f, dir).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	done(t, f, dir)
	if f.escrows[0] != "key-old/key-new" {
		t.Fatalf("the escrow made before the vault moved carried %q, want both keys", f.escrows[0])
	}
	for _, a := range f.audits {
		if strings.Contains(a, "key-old") || strings.Contains(a, "key-new") {
			t.Fatalf("the audit carries a key: %s", a)
		}
	}
	if len(f.audits) == 0 || !strings.Contains(strings.Join(f.audits, ";"), "staging") {
		t.Fatalf("the retire isn't audited by name: %v", f.audits)
	}
}

// The process can die before or after any call: a restart carries on, makes no
// second key, and ends with only the new set.
func TestARotationResumesAfterADeathAtEveryCall(t *testing.T) {
	probe := newFake(t)
	if err := runner(probe, t.TempDir()).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	total := probe.n
	for at := 1; at <= total; at++ {
		f, dir := newFake(t), t.TempDir()
		f.crashAt = at
		err := runner(f, dir).Run(context.Background())
		if err != nil && !errors.Is(err, errCrash) {
			t.Fatalf("call %d: %v", at, err)
		}
		f.crashAt = 0
		if err == nil {
			// A status read that dies is a vault not answering yet: the wait went
			// on and the rotation finished; a second run would be a new rotation.
			done(t, f, dir)
			continue
		}
		if err := runner(f, dir).Run(context.Background()); err != nil {
			t.Fatalf("call %d, resumed: %v", at, err)
		}
		if f.made != 1 {
			t.Fatalf("call %d (%s): %d keys made, calls %v", at, f.calls[at-1], f.made, f.calls)
		}
		done(t, f, dir)
	}
}

// A vault that can't verify leaves every key where it was and stops; nothing
// is dropped, replaced or retired, and a later run tries again.
func TestAFailedVerifyDeletesNothing(t *testing.T) {
	f, dir := newFake(t), t.TempDir()
	f.vaultState = "failing"
	err := runner(f, dir).Run(context.Background())
	if !errors.Is(err, rootrotate.ErrNotVerified) {
		t.Fatalf("%v", err)
	}
	if f.previous != "key-old" || f.current != "key-new" || f.canonical != "key-old" || f.staging != "key-new" || len(f.retired) != 0 {
		t.Fatalf("a key moved: previous=%s current=%s canonical=%s staging=%s retired=%v", f.previous, f.current, f.canonical, f.staging, f.retired)
	}
	if _, err := os.Stat(filepath.Join(dir, "rotate.json")); err != nil {
		t.Fatalf("the state to resume from is gone: %v", err)
	}
	f.vaultState = "none"
	if err := runner(f, dir).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	done(t, f, dir)
}

// A status from a vault pod that started before the restart is not an answer.
func TestAStatusFromBeforeTheRestartIsNotTrusted(t *testing.T) {
	f, dir := newFake(t), t.TempDir()
	r := runner(f, dir)
	r.Bound = 20 * time.Millisecond
	f.crashAt = 0
	// Hold the clock back so the pod looks older than the restart.
	stale := &staleFake{fake: f}
	r.Env = stale
	if err := r.Run(context.Background()); !errors.Is(err, rootrotate.ErrNotVerified) {
		t.Fatalf("%v", err)
	}
	if f.previous == "" {
		t.Fatal("the previous key was dropped on a stale status")
	}
}

type staleFake struct{ *fake }

func (s *staleFake) Status(ctx context.Context, notBefore time.Time) (rootrotate.VaultStatus, error) {
	return rootrotate.VaultStatus{State: rootrotate.StateVerified}, errors.New("the pod is older than the restart")
}
