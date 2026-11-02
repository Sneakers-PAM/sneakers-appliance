// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productspec

import (
	"strings"
	"testing"
)

const backupsYAML = `format: 2
phases:
  - {name: data, label: Data, stack: st-data, workloads: [db]}
  - {name: services, label: Services, stack: st-svc, workloads: [api]}
data:
  - {name: database, label: The database, path: db, wal: pgdata/pg_wal, wal_warn: 1GiB}
escrow:
  - {name: root-key, secret: app/keys, key: ROOT}
box_secrets:
  - secret: app/keys
    keys:
      - {key: ROOT, generate: key32}
backups:
  label: The database
  after: data
  cluster:
    namespace: app
    name: db
    host: /var/run/postgresql
    user: postgres
  claim: db-backup
  dir: postgres
  mount: /backup
  store: walg
  data: database
  pgdata: pgdata
  databases: [app_one]
  command: [/tools/agent, backup]
  status:
    lease: db-backup
    success: example/last-success
    failure: example/last-failure
    verify: example/last-verify
    verify_result: example/last-verify-result
    verify_ok: ok
  restore:
    env:
      MODE: restore
      FROM: "{set}"
      TARGET: "{point}"
    identity_lease: db
    identity_annotations: [example/system-identifier]
  checks:
    - {name: chain, database: app_one, file: backups/chain.sql}
`

func TestAProductDeclaresItsBackups(t *testing.T) {
	s, err := Parse([]byte(backupsYAML))
	if err != nil {
		t.Fatal(err)
	}
	b := s.Backups
	if b == nil || b.HostDir() != BackupRoot+"/postgres" || b.StoreHostDir() != BackupRoot+"/postgres/walg" || b.SetsHostDir() != BackupRoot+"/postgres/sets" {
		t.Fatalf("backups = %+v", b)
	}
	if got := b.PodSetStore("p1"); got != "/backup/sets/p1/store" {
		t.Fatalf("the pod sees the set at %s", got)
	}
	got := b.RestoreEnv("p1", "p1-at")
	if got["MODE"] != "restore" || got["FROM"] != "/backup/sets/p1/store" || got["TARGET"] != "p1-at" {
		t.Fatalf("restore env = %v", got)
	}
	if d, ok := s.BackupData(); !ok || d.Name != "database" {
		t.Fatalf("data path = %+v", d)
	}
	if l := s.BackupLater(); len(l) != 1 || l[0].Name != "services" {
		t.Fatalf("later = %+v", l)
	}
}

func TestABadBackupsDeclarationIsRefused(t *testing.T) {
	cases := map[string][2]string{
		"no label":             {"label: The database\n  after", "after"},
		"a dir that climbs":    {"dir: postgres", "dir: ../postgres"},
		"the data move's dir":  {"dir: postgres", "dir: data-move"},
		"a store that climbs":  {"store: walg", "store: ../walg"},
		"the sets as a store":  {"store: walg", "store: sets"},
		"an unknown phase":     {"after: data", "after: nowhere"},
		"a cluster elsewhere":  {"name: db\n", "name: api\n"},
		"an unknown data path": {"data: database", "data: elsewhere"},
		"no restore target":    {`TARGET: "{point}"`, `TARGET: fixed`},
		"no restore source":    {`FROM: "{set}"`, `FROM: fixed`},
		"a bad env name":       {"MODE: restore", "mode: restore"},
		"no identity lease":    {"identity_lease: db", "identity_lease: ''"},
		"a check elsewhere":    {"database: app_one, file", "database: other, file"},
		"no command":           {"command: [/tools/agent, backup]", "command: []"},
		"a relative mount":     {"mount: /backup", "mount: backup"},
		"no claim":             {"claim: db-backup", "claim: ''"},
		"a pgdata that climbs": {"pgdata: pgdata", "pgdata: ../pgdata"},
	}
	for name, c := range cases {
		y := strings.Replace(backupsYAML, c[0], c[1], 1)
		if y == backupsYAML {
			t.Fatalf("%s: the case changes nothing", name)
		}
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestABackupsDeclarationNeedsTheProductKeys(t *testing.T) {
	y := strings.Replace(backupsYAML, "escrow:\n  - {name: root-key, secret: app/keys, key: ROOT}\n", "", 1)
	if _, err := Parse([]byte(y)); err == nil {
		t.Fatal("a product with no escrowed key can't tell its own box from another")
	}
}
