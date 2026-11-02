// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productup_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/backupset"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productup"
)

const backedUpProduct = movingProduct + `data:
  - {name: database, label: The database, path: app-db, wal: pgdata/pg_wal, wal_warn: 1GiB}
escrow:
  - {name: root-key, secret: app/keys, key: ROOT}
box_secrets:
  - secret: app/keys
    keys: [{key: ROOT, generate: key32}]
backups:
  label: Restoring the database
  after: data
  cluster: {namespace: app, name: app-db, host: /var/run/postgresql, user: postgres}
  claim: app-db-backup
  dir: postgres
  mount: /backup
  store: walg
  data: database
  pgdata: pgdata
  command: [/tools/agent, backup]
  status: {lease: app-db-backup, success: s, failure: f, verify: v, verify_result: r, verify_ok: ok}
  restore:
    env: {FROM: "{set}", TARGET: "{point}"}
    identity_lease: app-db
`

type fakeRestore struct {
	status  backupset.Status
	asked   int
	svc     backupset.Services
	settled int
}

func (f *fakeRestore) Ask(svc backupset.Services) backupset.Status {
	f.asked++
	f.svc = svc
	return f.status
}

func (f *fakeRestore) Settle(context.Context) error { f.settled++; return nil }

func backedUpProbe(t *testing.T, c *fakeCluster) *productup.Probe {
	t.Helper()
	c.apiUp = true
	p, _ := movingProbe(t, c, &fakeMover{})
	if err := os.WriteFile(filepath.Join(p.Slot, productspec.File), []byte(backedUpProduct), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := productspec.Load(p.Slot); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestARestoreHoldsTheProductBeforeAnyPhase(t *testing.T) {
	c := newCluster()
	p := backedUpProbe(t, c)
	f := &fakeRestore{status: backupset.Status{Busy: true, Detail: "Restoring the database to p1"}}
	p.Restore = f
	r, err := p.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Step != productup.StepRestore || !strings.Contains(r.Detail, "p1") || !r.Unbounded {
		t.Fatalf("result = %+v", r)
	}
	var ids []string
	for _, s := range p.Steps() {
		ids = append(ids, s.ID)
	}
	if !slices.Contains(ids, productup.StepRestore) {
		t.Fatalf("steps %v", ids)
	}
}

func TestAProductWithNoRestoreGoesOn(t *testing.T) {
	c := newCluster()
	p := backedUpProbe(t, c)
	f := &fakeRestore{}
	p.Restore = f
	if r, err := p.Check(context.Background()); err != nil || r.Step == productup.StepRestore {
		t.Fatalf("result = %+v, %v", r, err)
	}
	if f.asked != 1 || f.settled != 0 {
		t.Fatalf("asked %d, settled %d", f.asked, f.settled)
	}
}
