// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/datamove"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/resources"
)

// resourcesBackend is the installed product's PostgreSQL cluster as the
// Resources page reads it: psql in the cluster's first pod with the
// installed bundle's k0s (internal/datamove's Exec), and the node count
// from the cluster.
type resourcesBackend struct {
	k0s, kubeconfig string
	lg              log.Logger
}

func (b *resourcesBackend) State(ctx context.Context, c resources.Cluster) (resources.State, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	pg := &resources.PG{Shell: datamove.Exec{Prefix: datamove.KubePrefix(b.k0s, b.kubeconfig), Logger: b.lg}, Cluster: c, Logger: b.lg}
	return pg.State(ctx)
}

// Settings are what the cluster has now. Until the box keeps the changes an
// admin makes in an overlay on the chart's values, the settings in force
// are read back from the running cluster: the servers connected, the
// volume's size and the parameters that differ from the server's own
// defaults. PgBouncer's sizes aren't readable that way, so they read as
// unknown.
func (b *resourcesBackend) Settings(_ context.Context, st resources.State) (resources.Settings, bool, error) {
	s := resources.Settings{Replicas: len(st.Replicas), StorageBytes: st.Storage.SizeBytes, Parameters: map[string]string{}}
	for _, p := range st.Parameters {
		if p.Value != p.Default && p.Unit == "" {
			s.Parameters[p.Name] = p.Value
		}
	}
	return s, false, nil
}

func (b *resourcesBackend) Nodes(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var out, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, b.k0s, "kubectl", "--kubeconfig", b.kubeconfig, "get", "nodes", "-o", "name") // #nosec G204 -- the installed bundle's k0s, fixed arguments
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("nodes: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	n := 0
	for _, l := range strings.Split(out.String(), "\n") {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	return n, nil
}
