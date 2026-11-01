// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productspec

import (
	"strings"
	"testing"
	"time"
)

const dataMoveYAML = `format: 2
phases:
  - {name: data, label: Data, stack: st-data, workloads: [old-db, new-db]}
  - {name: services, label: Services, stack: st-svc, workloads: [api]}
data_move:
  label: Moving the database
  after: data
  databases: [app_one, app_two]
  source:
    namespace: app
    name: old-db
    host: 127.0.0.1
    user: postgres
    password_env: POSTGRES_PASSWORD
  target:
    namespace: app
    name: new-db
    host: new-db-primary.app.svc
    port: 5433
    sslmode: require
    user: postgres
    password_env: POSTGRES_PASSWORD
  checks:
    - {name: chain, database: app_one, file: datamove/chain.sql}
  timeout: 3h
`

func parseDataMove(t *testing.T, y string) (Spec, error) {
	t.Helper()
	return Parse([]byte(y))
}

func TestADataMoveIsReadAsDeclared(t *testing.T) {
	s, err := parseDataMove(t, dataMoveYAML)
	if err != nil {
		t.Fatal(err)
	}
	m := s.DataMove
	if m == nil || m.After != "data" || m.Target.Host != "new-db-primary.app.svc" || m.Target.Port != 5433 || m.Target.SSLMode != "require" {
		t.Fatalf("%+v", m)
	}
	if m.Source.PortOrDefault() != 5432 || m.Source.SSLModeOrDefault() != "disable" || m.Source.ContainerOrDefault() != "postgres" {
		t.Fatalf("source defaults: %+v", m.Source)
	}
	if m.TimeoutOrDefault() != 3*time.Hour {
		t.Fatalf("timeout %v", m.TimeoutOrDefault())
	}
	if (DataMove{}).TimeoutOrDefault() != DefaultDataMoveTimeout {
		t.Fatal("default timeout")
	}
}

func TestAProductWithoutADataMoveHasNone(t *testing.T) {
	s, err := parseDataMove(t, "format: 2\n")
	if err != nil || s.DataMove != nil {
		t.Fatalf("%+v %v", s.DataMove, err)
	}
}

func TestABadDataMoveIsRefused(t *testing.T) {
	cases := map[string][2]string{
		"no phases":          {"phases:\n  - {name: data, label: Data, stack: st-data, workloads: [old-db, new-db]}\n  - {name: services, label: Services, stack: st-svc, workloads: [api]}\n", ""},
		"unknown phase":      {"after: data", "after: nope"},
		"last phase":         {"after: data", "after: services"},
		"no databases":       {"databases: [app_one, app_two]", "databases: []"},
		"bad database":       {"databases: [app_one, app_two]", "databases: [\"app; drop\"]"},
		"repeated database":  {"databases: [app_one, app_two]", "databases: [app_one, app_one]"},
		"same name":          {"name: new-db", "name: old-db"},
		"target not started": {"name: new-db", "name: other-db"},
		"source not started": {"name: old-db", "name: other-db"},
		"no target host":     {"host: new-db-primary.app.svc", "host: \"\""},
		"bad host":           {"host: new-db-primary.app.svc", "host: \"new db; rm\""},
		"bad sslmode":        {"sslmode: require", "sslmode: maybe"},
		"bad port":           {"port: 5433", "port: 70000"},
		"bad password env":   {"password_env: POSTGRES_PASSWORD\n  checks", "password_env: \"$(x)\"\n  checks"},
		"bad check file":     {"file: datamove/chain.sql", "file: ../chain.sql"},
		"check elsewhere":    {"database: app_one, file", "database: other, file"},
		"short timeout":      {"timeout: 3h", "timeout: 1s"},
		"long timeout":       {"timeout: 3h", "timeout: 999h"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseDataMove(t, strings.Replace(dataMoveYAML, c[0], c[1], 1)); err == nil {
				t.Fatal("not refused")
			}
		})
	}
}

func TestDataMoveLaterPhases(t *testing.T) {
	s, err := parseDataMove(t, dataMoveYAML)
	if err != nil {
		t.Fatal(err)
	}
	later := s.DataMoveLater()
	if len(later) != 1 || later[0].Name != "services" {
		t.Fatalf("%+v", later)
	}
	if (Spec{}).DataMoveLater() != nil {
		t.Fatal("no move, no later phases")
	}
}
