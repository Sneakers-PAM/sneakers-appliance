// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resources

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// Shell runs a tool in the cluster's first pod, as internal/datamove's Exec
// does: no password leaves the pod.
type Shell interface {
	Run(ctx context.Context, c productspec.DataCluster, argv []string, in io.Reader, out io.Writer) error
}

// Replica is one PostgreSQL server of the cluster.
type Replica struct {
	Name string
	// Role is primary or replica.
	Role string
	// State is the replication state the primary reports (streaming,
	// catchup and so on); empty for the primary itself.
	State   string
	Healthy bool
	// LagBytes is how far the replica's replay is behind what the primary
	// sent.
	LagBytes int64
}

// Storage is the data volume.
type Storage struct {
	// SizeBytes is the volume's size; 0 when it can't be read.
	SizeBytes int64
	// UsedBytes is what the databases hold.
	UsedBytes int64
}

// Parameter is one PostgreSQL setting the server has.
type Parameter struct {
	Name  string
	Value string
	// Unit is the unit Value is in (8kB, kB, ms), empty for none.
	Unit string
	// Default is the server's built-in value, in the same unit.
	Default string
	// NeedsRestart is true for a setting read only at start.
	NeedsRestart bool
	// PendingRestart is true when the value in the configuration isn't the
	// one the running server has yet.
	PendingRestart bool
	// Known is true when the box checks edits to this parameter.
	Known bool
}

// State is what the cluster is doing now.
type State struct {
	Replicas   []Replica
	Storage    Storage
	Parameters []Parameter
}

// PG reads a cluster's state with psql in its first pod.
type PG struct {
	Shell   Shell
	Cluster productspec.DataCluster
	Logger  log.Logger
}

// maintenanceDB is the database the queries connect to.
const maintenanceDB = "postgres"

func (p *PG) psql(ctx context.Context, sql string) (string, error) {
	var out bytes.Buffer
	if err := p.Shell.Run(ctx, p.Cluster, []string{"psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-F", "\t", "-d", maintenanceDB, "-c", sql}, nil, &out); err != nil {
		return "", err
	}
	return out.String(), nil
}

func rows(s string) [][]string {
	var out [][]string
	for _, l := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if l == "" {
			continue
		}
		out = append(out, strings.Split(l, "\t"))
	}
	return out
}

func (p *PG) logger() log.Logger {
	if p.Logger == nil {
		return log.Nop()
	}
	return p.Logger
}

// State reads the replicas, the storage and every parameter. The volume's
// size is best effort: without it the page shows the size it set.
func (p *PG) State(ctx context.Context) (State, error) {
	start := time.Now()
	var st State
	name := p.Cluster.Name + "-0"

	out, err := p.psql(ctx, "SELECT pg_is_in_recovery();")
	if err != nil {
		return st, fmt.Errorf("resources: the cluster can't be read: %w", err)
	}
	first := Replica{Name: name, Role: "primary", Healthy: true}
	if strings.TrimSpace(out) == "t" {
		first.Role = "replica"
	}
	st.Replicas = append(st.Replicas, first)

	out, err = p.psql(ctx, "SELECT application_name, state, COALESCE(pg_wal_lsn_diff(sent_lsn, replay_lsn), 0)::bigint FROM pg_stat_replication ORDER BY application_name;")
	if err != nil {
		return st, fmt.Errorf("resources: the replicas can't be read: %w", err)
	}
	for _, r := range rows(out) {
		if len(r) < 3 {
			continue
		}
		lag, _ := strconv.ParseInt(r[2], 10, 64)
		st.Replicas = append(st.Replicas, Replica{Name: r[0], Role: "replica", State: r[1], Healthy: r[1] == "streaming", LagBytes: lag})
	}

	out, err = p.psql(ctx, "SELECT COALESCE(sum(pg_database_size(datname)), 0)::bigint FROM pg_database;")
	if err != nil {
		return st, fmt.Errorf("resources: the storage can't be read: %w", err)
	}
	st.Storage.UsedBytes, _ = strconv.ParseInt(strings.TrimSpace(out), 10, 64)
	st.Storage.SizeBytes = p.volumeSize(ctx)

	out, err = p.psql(ctx, "SELECT name, setting, COALESCE(unit, ''), COALESCE(boot_val, ''), context, pending_restart FROM pg_settings ORDER BY name;")
	if err != nil {
		return st, fmt.Errorf("resources: the parameters can't be read: %w", err)
	}
	for _, r := range rows(out) {
		if len(r) < 6 {
			continue
		}
		_, known := catalog[r[0]]
		st.Parameters = append(st.Parameters, Parameter{Name: r[0], Value: r[1], Unit: r[2], Default: r[3], NeedsRestart: r[4] == "postmaster", PendingRestart: r[5] == "t", Known: known})
	}
	p.logger().Debug("resources: state read", log.F("cluster", p.Cluster.Name), log.F("replicas", len(st.Replicas)), log.F("parameters", len(st.Parameters)), log.F("duration", time.Since(start).String()))
	return st, nil
}

// volumeSize is the size of the filesystem PGDATA is on, or 0.
func (p *PG) volumeSize(ctx context.Context) int64 {
	var out bytes.Buffer
	err := p.Shell.Run(ctx, p.Cluster, []string{"sh", "-c", `df -P -B1 "${PGDATA:-/var/lib/postgresql/data}" | tail -n 1`}, nil, &out)
	if err != nil {
		p.logger().Debug("resources: the volume's size can't be read", log.F("error", err.Error()))
		return 0
	}
	f := strings.Fields(out.String())
	if len(f) < 2 {
		return 0
	}
	n, _ := strconv.ParseInt(f[1], 10, 64)
	return n
}
