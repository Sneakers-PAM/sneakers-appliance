// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package backupset

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/datamove"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

const (
	// goneBound bounds the wait for a stopping pod.
	goneBound = 5 * time.Minute
	// primaryBound bounds a restore's replay; a target the archive can't
	// reach never gets there, and the box goes back.
	primaryBound = 2 * time.Hour
)

// Cluster is Engine and Kube on the box: kubectl, and the tools in the
// cluster's own pod.
type Cluster struct {
	// Tools runs in the cluster's first pod.
	Tools datamove.Exec
	// Kubectl runs kubectl and answers its output.
	Kubectl func(ctx context.Context, args ...string) ([]byte, error)
	// Every is how often a wait looks again; 0 is 2 seconds.
	Every time.Duration
}

const maintenanceDB = "postgres"

func (c *Cluster) psql(ctx context.Context, b productspec.Backups, db, sql string) (string, error) {
	var out bytes.Buffer
	argv := []string{"psql", "-d", db, "-qtAX", "-v", "ON_ERROR_STOP=1", "-f", "-"}
	err := c.Tools.Run(ctx, b.Cluster, argv, strings.NewReader(sql), &out)
	return strings.TrimSpace(out.String()), err
}

func literal(s string) string { return `'` + strings.ReplaceAll(s, `'`, `''`) + `'` }

// RestorePoint implements Engine.
func (c *Cluster) RestorePoint(ctx context.Context, b productspec.Backups, point string) (string, uint32, error) {
	got, err := c.psql(ctx, b, maintenanceDB, `SELECT pg_create_restore_point(`+literal(point)+`), (SELECT timeline_id FROM pg_control_checkpoint());`)
	if err != nil {
		return "", 0, err
	}
	lsn, tl, ok := strings.Cut(got, "|")
	if !ok {
		return "", 0, fmt.Errorf("the restore point came back as %q", got)
	}
	t, err := strconv.ParseUint(tl, 10, 32)
	if err != nil {
		return "", 0, fmt.Errorf("the timeline came back as %q", tl)
	}
	// Closing the segment sends the point to the archive now, not at the
	// archive timeout.
	if _, err := c.psql(ctx, b, maintenanceDB, `SELECT pg_switch_wal();`); err != nil {
		return "", 0, err
	}
	return lsn, uint32(t), nil // #nosec G115 -- parsed as 32 bits
}

// RequestBase implements Engine.
func (c *Cluster) RequestBase(ctx context.Context, b productspec.Backups) error {
	var out bytes.Buffer
	return c.Tools.Run(ctx, b.Cluster, b.Command, nil, &out)
}

// Annotations implements Engine.
func (c *Cluster) Annotations(ctx context.Context, b productspec.Backups) (map[string]string, error) {
	raw, err := c.Kubectl(ctx, "get", "lease", b.Status.Lease, "--namespace", b.Cluster.Namespace, "-o", "jsonpath={.metadata.annotations}")
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	if len(bytes.TrimSpace(raw)) == 0 {
		return out, nil
	}
	return out, json.Unmarshal(raw, &out)
}

// KeyDigest implements Engine. The key is read, hashed and dropped; a digest
// of 32 random bytes says nothing about them.
func (c *Cluster) KeyDigest(ctx context.Context, k productspec.EscrowKey) (string, error) {
	raw, err := c.Kubectl(ctx, "get", "secret", k.SecretName(), "--namespace", k.Namespace(), "-o", "jsonpath={.data."+k.Key+"}")
	if err != nil {
		return "", errors.New("the Secret doesn't read")
	}
	v, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(v) == 0 {
		return "", errors.New("the Secret holds no such key")
	}
	h := sha256.New()
	h.Write([]byte("sneakers backup set key\x00"))
	h.Write(v)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (c *Cluster) workload(b productspec.Backups) string { return "statefulset/" + b.Cluster.Name }

// Stop implements Kube.
func (c *Cluster) Stop(ctx context.Context, b productspec.Backups) error {
	if _, err := c.Kubectl(ctx, "scale", "--namespace", b.Cluster.Namespace, c.workload(b), "--replicas=0"); err != nil && !notFound(err) {
		return err
	}
	_, err := c.Kubectl(ctx, "wait", "--namespace", b.Cluster.Namespace, "--for=delete", "pod/"+b.Cluster.Name+"-0", "--timeout="+goneBound.String())
	if err != nil && !notFound(err) {
		return err
	}
	return nil
}

// Start implements Kube.
func (c *Cluster) Start(ctx context.Context, b productspec.Backups) error {
	_, err := c.Kubectl(ctx, "scale", "--namespace", b.Cluster.Namespace, c.workload(b), "--replicas=1")
	return err
}

// SetEnv implements Kube.
func (c *Cluster) SetEnv(ctx context.Context, b productspec.Backups, env map[string]string) error {
	args := []string{"set", "env", "--namespace", b.Cluster.Namespace, c.workload(b), "--containers=" + b.Cluster.ContainerOrDefault()}
	for _, k := range sortedKeys(env) {
		args = append(args, k+"="+env[k])
	}
	_, err := c.Kubectl(ctx, args...)
	return err
}

// UnsetEnv implements Kube.
func (c *Cluster) UnsetEnv(ctx context.Context, b productspec.Backups, names []string) error {
	args := []string{"set", "env", "--namespace", b.Cluster.Namespace, c.workload(b), "--containers=" + b.Cluster.ContainerOrDefault()}
	for _, k := range names {
		args = append(args, k+"-")
	}
	if _, err := c.Kubectl(ctx, args...); err != nil && !notFound(err) {
		return err
	}
	return nil
}

// ClearIdentity implements Kube.
func (c *Cluster) ClearIdentity(ctx context.Context, b productspec.Backups) error {
	args := []string{"annotate", "--namespace", b.Cluster.Namespace, "lease", b.Restore.IdentityLease}
	for _, k := range b.Restore.IdentityAnnotations {
		args = append(args, k+"-")
	}
	if len(b.Restore.IdentityAnnotations) == 0 {
		return nil
	}
	_, err := c.Kubectl(ctx, args...)
	return err
}

// WaitPrimary implements Kube.
func (c *Cluster) WaitPrimary(ctx context.Context, b productspec.Backups) error {
	ctx, cancel := context.WithTimeout(ctx, primaryBound)
	defer cancel()
	every := c.Every
	if every <= 0 {
		every = 2 * time.Second
	}
	var last error
	for {
		got, err := c.psql(ctx, b, maintenanceDB, `SELECT pg_is_in_recovery();`)
		if err == nil && got == "f" {
			return nil
		}
		if err != nil {
			last = err
		} else {
			last = errors.New("it's still replaying")
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s didn't come back: %w", b.Cluster.Name, last)
		case <-time.After(every):
		}
	}
}

// Check implements Kube.
func (c *Cluster) Check(ctx context.Context, b productspec.Backups, db string, sql []byte) (string, error) {
	return c.psql(ctx, b, db, string(sql))
}

func notFound(err error) bool {
	return strings.Contains(err.Error(), "NotFound") || strings.Contains(err.Error(), "not found")
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
