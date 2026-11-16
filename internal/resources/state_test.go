// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resources

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// fakeShell answers the queries State asks, by a word in each.
type fakeShell struct {
	answers map[string]string
	err     error
	ran     [][]string
}

func (f *fakeShell) Run(_ context.Context, _ productspec.DataCluster, argv []string, _ io.Reader, out io.Writer) error {
	f.ran = append(f.ran, argv)
	if f.err != nil {
		return f.err
	}
	joined := strings.Join(argv, " ")
	for k, v := range f.answers {
		if strings.Contains(joined, k) {
			_, _ = io.WriteString(out, v)
			return nil
		}
	}
	return errors.New("unexpected command: " + joined)
}

func cluster() productspec.DataCluster {
	return productspec.DataCluster{Namespace: "sneakers", Name: "sneakers-pgha", Host: "/var/run/postgresql", User: "postgres"}
}

func healthy() *fakeShell {
	return &fakeShell{answers: map[string]string{
		"pg_is_in_recovery":   "f\n",
		"pg_stat_replication": "sneakers-pgha-1\tstreaming\t2048\nsneakers-pgha-2\tcatchup\t900000\n",
		"pg_settings": "max_connections\t100\t\t100\tpostmaster\tf\n" +
			"shared_buffers\t32768\t8kB\t16384\tpostmaster\tt\n" +
			"work_mem\t4096\tkB\t4096\tuser\tf\n" +
			"pg_stat_statements.max\t5000\t\t5000\tpostmaster\tf\n",
		"pg_database_size": "123456789\n",
		"df -P":            "/dev/sdb 21474836480 123461632 21351374848 1% /var/lib/postgresql\n",
	}}
}

func TestStateReadsReplicasStorageAndEveryParameter(t *testing.T) {
	sh := healthy()
	s, err := (&PG{Shell: sh, Cluster: cluster()}).State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Replicas) != 3 || s.Replicas[0].Name != "sneakers-pgha-0" || s.Replicas[0].Role != "primary" || !s.Replicas[0].Healthy {
		t.Fatalf("replicas %+v", s.Replicas)
	}
	if r := s.Replicas[1]; r.Name != "sneakers-pgha-1" || r.Role != "replica" || !r.Healthy || r.LagBytes != 2048 {
		t.Fatalf("replica 1 %+v", r)
	}
	if r := s.Replicas[2]; r.State != "catchup" || r.Healthy || r.LagBytes != 900000 {
		t.Fatalf("a replica that's catching up isn't healthy: %+v", r)
	}
	if s.Storage.UsedBytes != 123456789 || s.Storage.SizeBytes != 21474836480 {
		t.Fatalf("storage %+v", s.Storage)
	}
	if len(s.Parameters) != 4 {
		t.Fatalf("parameters %+v", s.Parameters)
	}
	by := map[string]Parameter{}
	for _, p := range s.Parameters {
		by[p.Name] = p
	}
	if p := by["shared_buffers"]; p.Value != "32768" || p.Unit != "8kB" || p.Default != "16384" || !p.NeedsRestart || !p.PendingRestart || !p.Known {
		t.Fatalf("shared_buffers %+v", p)
	}
	if p := by["work_mem"]; p.NeedsRestart || p.PendingRestart || !p.Known {
		t.Fatalf("work_mem %+v", p)
	}
	if p := by["pg_stat_statements.max"]; p.Known || !p.NeedsRestart {
		t.Fatalf("an extension's parameter is unknown to the box's catalog, but the server says it needs a restart: %+v", p)
	}
}

func TestStateUsesTheClusterToolsAndNoShellOfItsOwn(t *testing.T) {
	sh := healthy()
	if _, err := (&PG{Shell: sh, Cluster: cluster()}).State(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, argv := range sh.ran {
		if argv[0] != "psql" && argv[0] != "sh" {
			t.Errorf("ran %v", argv)
		}
	}
}

func TestAReplicaOfAReplicaCluster(t *testing.T) {
	sh := healthy()
	sh.answers["pg_is_in_recovery"] = "t\n"
	s, err := (&PG{Shell: sh, Cluster: cluster()}).State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.Replicas[0].Role != "replica" {
		t.Fatalf("%+v", s.Replicas[0])
	}
}

func TestStateAnswersWhatItCouldReadAndSaysWhatItCouldnt(t *testing.T) {
	sh := healthy()
	sh.err = errors.New("the pod isn't there")
	_, err := (&PG{Shell: sh, Cluster: cluster()}).State(context.Background())
	if err == nil || !strings.Contains(err.Error(), "the pod isn't there") {
		t.Fatalf("%v", err)
	}
	// A volume that df can't read still gives the rest.
	sh = healthy()
	delete(sh.answers, "df -P")
	sh.answers["sh -c"] = ""
	s, err := (&PG{Shell: sh, Cluster: cluster()}).State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.Storage.SizeBytes != 0 || s.Storage.UsedBytes != 123456789 {
		t.Fatalf("storage %+v", s.Storage)
	}
}
