// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resources

import (
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

const gi = int64(1) << 30

func current() Settings {
	return Settings{
		Replicas:     1,
		StorageBytes: 20 * gi,
		Parameters:   map[string]string{"shared_buffers": "256MB"},
		Pools:        Pools{DefaultPoolSize: 20, MaxClientConn: 100},
	}
}

func staged(f func(*Settings)) Settings {
	s := current()
	s.Parameters = map[string]string{"shared_buffers": "256MB"}
	f(&s)
	return s
}

func TestNothingChangedIsAnEmptyPlan(t *testing.T) {
	p, err := Preview(current(), current(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Changes) != 0 || len(p.Warnings) != 0 {
		t.Fatalf("%+v", p)
	}
}

func TestEachChangeNamesItsBeforeAndAfter(t *testing.T) {
	p, err := Preview(current(), staged(func(s *Settings) {
		s.Replicas = 2
		s.StorageBytes = 40 * gi
		s.Parameters["work_mem"] = "16MB"
		s.Parameters["shared_buffers"] = "512MB"
		s.Pools.DefaultPoolSize = 40
	}), 3)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Change{}
	for _, c := range p.Changes {
		got[c.Field] = c
	}
	for field, want := range map[string][2]string{
		"replicas":                    {"1", "2"},
		"storage":                     {"20Gi", "40Gi"},
		"parameters.work_mem":         {"", "16MB"},
		"parameters.shared_buffers":   {"256MB", "512MB"},
		"pgbouncer.default_pool_size": {"20", "40"},
	} {
		c, ok := got[field]
		if !ok || c.Before != want[0] || c.After != want[1] {
			t.Errorf("%s: %+v, want %v", field, c, want)
		}
	}
	if len(p.Changes) != 5 {
		t.Errorf("%d changes: %+v", len(p.Changes), p.Changes)
	}
	// shared_buffers needs a restart; work_mem doesn't.
	if !got["parameters.shared_buffers"].RestartRequired || got["parameters.work_mem"].RestartRequired {
		t.Errorf("restart flags: %+v %+v", got["parameters.shared_buffers"], got["parameters.work_mem"])
	}
}

func TestAReplicaCountIsNeverBlockedButWarnsPastTheNodes(t *testing.T) {
	for _, n := range []int{2, 3, 7} {
		p, err := Preview(current(), staged(func(s *Settings) { s.Replicas = n }), 1)
		if err != nil {
			t.Fatalf("%d replicas: %v", n, err)
		}
		if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "node") {
			t.Fatalf("%d replicas on 1 node: %v", n, p.Warnings)
		}
	}
	p, err := Preview(current(), staged(func(s *Settings) { s.Replicas = 3 }), 3)
	if err != nil || len(p.Warnings) != 0 {
		t.Fatalf("3 replicas on 3 nodes: %v %v", p.Warnings, err)
	}
	if _, err := Preview(current(), staged(func(s *Settings) { s.Replicas = 0 }), 1); !codes.Is(err, codes.ResourcesInvalid) {
		t.Fatalf("no replicas at all isn't a database: %v", err)
	}
}

func TestStorageOnlyGrows(t *testing.T) {
	if _, err := Preview(current(), staged(func(s *Settings) { s.StorageBytes = 10 * gi }), 1); !codes.Is(err, codes.ResourcesInvalid) || !strings.Contains(err.Error(), "grow") {
		t.Fatalf("shrinking: %v", err)
	}
	if _, err := Preview(current(), staged(func(s *Settings) { s.StorageBytes = 0 }), 1); !codes.Is(err, codes.ResourcesInvalid) {
		t.Fatalf("zero: %v", err)
	}
	if _, err := Preview(current(), staged(func(s *Settings) { s.StorageBytes = 20 * gi }), 1); err != nil {
		t.Fatalf("the same size: %v", err)
	}
}

func TestKnownParametersAreTypeCheckedAndUnknownOnesPassWithAWarning(t *testing.T) {
	bad := map[string]string{
		"shared_buffers":       "lots",
		"max_connections":      "1.5",
		"autovacuum":           "maybe",
		"synchronous_commit":   "sometimes",
		"random_page_cost":     "cheap",
		"statement_timeout":    "5 fortnights",
		"checkpoint_timeout":   "-1",
		"effective_cache_size": "",
	}
	for k, v := range bad {
		_, err := Preview(current(), staged(func(s *Settings) { s.Parameters[k] = v }), 1)
		if !codes.Is(err, codes.ResourcesInvalid) || !strings.Contains(err.Error(), k) {
			t.Errorf("%s=%q: %v", k, v, err)
		}
	}
	good := map[string]string{
		"shared_buffers": "1GB", "max_connections": "200", "autovacuum": "off", "synchronous_commit": "remote_write",
		"random_page_cost": "1.1", "statement_timeout": "30s", "work_mem": "64MB", "log_statement": "ddl",
	}
	for k, v := range good {
		if _, err := Preview(current(), staged(func(s *Settings) { s.Parameters[k] = v }), 1); err != nil {
			t.Errorf("%s=%q: %v", k, v, err)
		}
	}
	p, err := Preview(current(), staged(func(s *Settings) { s.Parameters["pg_stat_statements.max"] = "10000" }), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "pg_stat_statements.max") {
		t.Fatalf("unknown parameter: %v", p.Warnings)
	}
}

func TestAParameterNameOrValueThatCouldBreakTheConfigIsRefused(t *testing.T) {
	for name, v := range map[string]string{
		"work_mem\nshared_buffers": "1MB",
		"Work Mem":                 "1MB",
		"":                         "1MB",
		"x=y":                      "1",
	} {
		if _, err := Preview(current(), staged(func(s *Settings) { s.Parameters[name] = v }), 1); !codes.Is(err, codes.ResourcesInvalid) {
			t.Errorf("name %q: %v", name, err)
		}
	}
	for _, v := range []string{"a\nb", "a'b", "a\x00b", strings.Repeat("x", 300)} {
		if _, err := Preview(current(), staged(func(s *Settings) { s.Parameters["application_name"] = v }), 1); !codes.Is(err, codes.ResourcesInvalid) {
			t.Errorf("value %q: %v", v, err)
		}
	}
}

func TestPoolSizesAreNonNegativeAndTheDefaultAtLeastOne(t *testing.T) {
	for _, f := range []func(*Settings){
		func(s *Settings) { s.Pools.DefaultPoolSize = 0 },
		func(s *Settings) { s.Pools.MinPoolSize = -1 },
		func(s *Settings) { s.Pools.MaxClientConn = 0 },
	} {
		if _, err := Preview(current(), staged(f), 1); !codes.Is(err, codes.ResourcesInvalid) {
			t.Errorf("%v", err)
		}
	}
	p, err := Preview(current(), staged(func(s *Settings) { s.Pools.MinPoolSize = 50 }), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "min_pool_size") {
		t.Fatalf("a minimum above the default pool: %v", p.Warnings)
	}
}

func TestSizesParse(t *testing.T) {
	for in, want := range map[string]int64{"20Gi": 20 * gi, "512Mi": 512 << 20, "1Ti": 1 << 40, "1048576": 1 << 20} {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("%q: %d %v", in, got, err)
		}
	}
	for _, in := range []string{"", "Gi", "-1Gi", "1.5Gi", "20GB", "20 Gi", "99999999Ti"} {
		if _, err := ParseSize(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
	if FormatSize(20*gi) != "20Gi" || FormatSize(1536<<20) != "1536Mi" || FormatSize(1000) != "1000" {
		t.Errorf("%s %s %s", FormatSize(20*gi), FormatSize(1536<<20), FormatSize(1000))
	}
}
