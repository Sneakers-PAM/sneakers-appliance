// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package backupset

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

type fakeKube struct {
	mu       sync.Mutex
	calls    []string
	env      map[string]string
	failAt   string
	checkOut string
	onStart  func()
	block    chan struct{}
}

func (k *fakeKube) call(s string) error {
	k.mu.Lock()
	k.calls = append(k.calls, s)
	fail, block := k.failAt, k.block
	k.mu.Unlock()
	if block != nil && s == "wait" {
		<-block
	}
	if s == fail {
		return errors.New("failed at " + s)
	}
	return nil
}

func (k *fakeKube) Stop(context.Context, productspec.Backups) error { return k.call("stop") }
func (k *fakeKube) Start(context.Context, productspec.Backups) error {
	if k.onStart != nil {
		k.onStart()
	}
	return k.call("start")
}
func (k *fakeKube) SetEnv(_ context.Context, _ productspec.Backups, env map[string]string) error {
	k.mu.Lock()
	k.env = env
	k.mu.Unlock()
	return k.call("env")
}
func (k *fakeKube) UnsetEnv(context.Context, productspec.Backups, []string) error {
	k.mu.Lock()
	k.env = nil
	k.mu.Unlock()
	return k.call("unset")
}
func (k *fakeKube) ClearIdentity(context.Context, productspec.Backups) error {
	return k.call("identity")
}
func (k *fakeKube) WaitPrimary(context.Context, productspec.Backups) error { return k.call("wait") }
func (k *fakeKube) Check(context.Context, productspec.Backups, string, []byte) (string, error) {
	return k.checkOut, k.call("check")
}

type stopper struct{ n int }

func (s *stopper) Stop(context.Context) error { s.n++; return nil }

type box struct {
	*fixture
	r      *Restorer
	k      *fakeKube
	svc    *stopper
	data   string
	mf     Manifest
	audits []string
}

func newBox(t *testing.T) *box {
	t.Helper()
	f := newFixture(t)
	f.archive(t)
	root := t.TempDir()
	f.spec.Data = []productspec.DataPath{{Name: "database", Path: "db"}}
	f.spec.Backups.Data, f.spec.Backups.PGData = "database", "pgdata"
	f.spec.Backups.Restore.Env = map[string]string{"FROM": "{set}", "TARGET": "{point}"}
	f.spec.Backups.Checks = []productspec.DataCheck{{Name: "chain", Database: "app", File: "chain.sql"}}
	f.m.Spec = func() (productspec.Spec, error) { return f.spec, nil }
	b := &box{fixture: f, k: &fakeKube{checkOut: "ok"}, svc: &stopper{}, data: filepath.Join(root, "db", "pgdata")}
	if err := os.MkdirAll(b.data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.data, "live"), []byte("the box's own data"), 0o600); err != nil {
		t.Fatal(err)
	}
	slot := t.TempDir()
	if err := os.WriteFile(filepath.Join(slot, "chain.sql"), []byte("SELECT 'ok'"), 0o600); err != nil {
		t.Fatal(err)
	}
	mf, err := f.m.Create(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	b.mf = mf
	b.r = &Restorer{Spec: f.m.Spec, Engine: f.e, Kube: b.k, Slot: slot, Journal: filepath.Join(root, JournalFile), DataRoot: root,
		Audit: func(a string, _ map[string]string) { b.audits = append(b.audits, a) }}
	return b
}

// settle asks until the restore lets the product go.
func (b *box) settle(t *testing.T) Journal {
	t.Helper()
	for range 2000 {
		if !b.r.Ask(b.svc).Busy {
			j, err := b.r.Read()
			if err != nil {
				t.Fatal(err)
			}
			return j
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("the restore didn't end")
	return Journal{}
}

func (b *box) wholeData(t *testing.T) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(b.data, "live"))
	if err != nil || string(got) != "the box's own data" {
		t.Fatalf("the box's data: %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(b.b.StoreHostDir(), walDir)); err != nil {
		t.Fatalf("the archive isn't back: %v", err)
	}
	b.k.mu.Lock()
	defer b.k.mu.Unlock()
	if b.k.env != nil {
		t.Fatalf("the restore's env stayed: %v", b.k.env)
	}
}

func TestARestoreGoesThroughAndSettles(t *testing.T) {
	b := newBox(t)
	b.k.onStart = func() {
		if err := os.MkdirAll(b.data, 0o700); err != nil {
			t.Error(err)
		}
	}
	if err := b.r.Request(context.Background(), "s1", "owner"); err != nil {
		t.Fatal(err)
	}
	j := b.settle(t)
	if j.State != StateSettling || j.Why != "" {
		t.Fatalf("journal = %+v", j)
	}
	if got := strings.Join(b.calls(), " "); !strings.Contains(got, "stop identity env start wait check stop unset") {
		t.Fatalf("calls = %s", got)
	}
	if b.svc.n == 0 {
		t.Fatal("the services weren't stopped")
	}
	if _, err := os.Stat(b.data + asideSuffix); err != nil {
		t.Fatalf("the data wasn't kept until the box settled: %v", err)
	}
	if err := b.r.Settle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(b.data + asideSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the data moved aside stayed: %v", err)
	}
	if j, _ := b.r.Read(); j.State != StateDone || b.e.bases != 1 {
		t.Fatalf("journal %+v, base backups %d", j, b.e.bases)
	}
	if strings.Join(b.audits, " ") != "product.backup.restore.start product.backup.restore.done" {
		t.Fatalf("audit = %v", b.audits)
	}
}

func TestAFailureAtEveryStepLeavesTheBoxItsData(t *testing.T) {
	for _, at := range []string{"stop", "identity", "env", "start", "wait", "check", "unset"} {
		t.Run(at, func(t *testing.T) {
			b := newBox(t)
			if at != "stop" {
				b.k.failAt = at
			} else {
				// A Stop that always fails can't go back; once is the case.
				b.k.failAt = ""
				b.svc = &stopper{}
				b.k.checkOut = "the chain is broken"
			}
			if err := b.r.Request(context.Background(), "s1", "owner"); err != nil {
				t.Fatal(err)
			}
			if at == "unset" {
				// The way back unsets too, so this one fails once.
				go func() {
					for !strings.Contains(strings.Join(b.calls(), " "), "unset") {
						time.Sleep(time.Millisecond)
					}
					b.k.mu.Lock()
					b.k.failAt = ""
					b.k.mu.Unlock()
				}()
			}
			j := b.settle(t)
			if j.State != StateFailed || j.Why == "" {
				t.Fatalf("journal = %+v", j)
			}
			b.wholeData(t)
			if len(b.audits) != 2 || b.audits[1] != "product.backup.restore.failed" {
				t.Fatalf("audit = %v", b.audits)
			}
		})
	}
}

func (b *box) calls() []string {
	b.k.mu.Lock()
	defer b.k.mu.Unlock()
	return append([]string{}, b.k.calls...)
}

func TestARestoreCutOffGoesBack(t *testing.T) {
	b := newBox(t)
	b.k.block = make(chan struct{})
	if err := b.r.Request(context.Background(), "s1", "owner"); err != nil {
		t.Fatal(err)
	}
	if !b.r.Ask(b.svc).Busy {
		t.Fatal("not busy")
	}
	for !strings.Contains(strings.Join(b.calls(), " "), "wait") {
		time.Sleep(time.Millisecond)
	}
	if err := os.MkdirAll(b.data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.data, "partial"), []byte("half a restore"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A new process, as after a power loss, reads the journal.
	r2 := &Restorer{Spec: b.r.Spec, Engine: b.r.Engine, Kube: &fakeKube{}, Slot: b.r.Slot, Journal: b.r.Journal, DataRoot: b.r.DataRoot, Audit: b.r.Audit}
	b.r = r2
	b.k = r2.Kube.(*fakeKube)
	j := b.settle(t)
	if j.State != StateFailed || !strings.Contains(j.Why, "cut off") {
		t.Fatalf("journal = %+v", j)
	}
	b.wholeData(t)
	if _, err := os.Stat(filepath.Join(b.data, "partial")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the partial restore stayed")
	}
}

func TestAProductThatDoesntComeUpGoesBack(t *testing.T) {
	b := newBox(t)
	clock := time.Now()
	b.r.Now = func() time.Time { return clock }
	if err := b.r.Request(context.Background(), "s1", "owner"); err != nil {
		t.Fatal(err)
	}
	if j := b.settle(t); j.State != StateSettling {
		t.Fatalf("journal = %+v", j)
	}
	clock = clock.Add(settleBound + time.Minute)
	j := b.settle(t)
	if j.State != StateFailed {
		t.Fatalf("journal = %+v", j)
	}
	b.wholeData(t)
}

func TestARestoreOntoAnotherBoxIsRefused(t *testing.T) {
	b := newBox(t)
	b.e.keys = map[string]string{"root-key": "another box's"}
	err := b.r.Request(context.Background(), "s1", "owner")
	if codeOf(err) == 0 || !strings.Contains(err.Error(), "different box") {
		t.Fatalf("got %v", err)
	}
	if j, _ := b.r.Read(); j.State != "" {
		t.Fatalf("a refusal left a journal: %+v", j)
	}
	if len(b.k.calls) != 0 {
		t.Fatalf("a refusal touched the cluster: %v", b.k.calls)
	}
}

func TestARestoreThatWontFitIsRefused(t *testing.T) {
	b := newBox(t)
	b.r.Avail = func(string) (uint64, error) { return 1 << 20, nil }
	if err := b.r.Request(context.Background(), "s1", "owner"); err == nil || !strings.Contains(err.Error(), "needs") {
		t.Fatalf("got %v", err)
	}
}

func TestOneRestoreAtATime(t *testing.T) {
	b := newBox(t)
	if err := b.r.Request(context.Background(), "s1", "owner"); err != nil {
		t.Fatal(err)
	}
	if err := b.r.Request(context.Background(), "s1", "owner"); err == nil {
		t.Fatal("a second restore was taken")
	}
}
