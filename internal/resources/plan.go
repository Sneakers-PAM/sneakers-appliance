// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package resources is the product's PostgreSQL settings as the Resources
// page edits them: the replica count, every postgresql.parameters entry,
// PgBouncer's pool sizes and the storage size. This file is the rules: what
// a change is, what it costs and what is refused. Nothing blocks a replica
// count; storage only grows; a parameter the box knows is type-checked and
// one it doesn't know passes with a warning (docs/resources.md).
package resources

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// Pools are PgBouncer's pool sizes.
type Pools struct {
	DefaultPoolSize int
	MinPoolSize     int
	ReservePoolSize int
	MaxClientConn   int
	MaxDBConns      int
}

// Settings are the settings the page edits.
type Settings struct {
	Replicas     int
	StorageBytes int64
	// Parameters are the postgresql.parameters entries, by name.
	Parameters map[string]string
	Pools      Pools
}

// Change is one setting that differs.
type Change struct {
	// Field is replicas, storage, parameters.<name> or pgbouncer.<name>.
	Field         string
	Before, After string
	// RestartRequired is true for a parameter PostgreSQL reads only at
	// start.
	RestartRequired bool
}

// Plan is what applying staged settings would do.
type Plan struct {
	Changes  []Change
	Warnings []string
}

func invalid(format string, args ...any) error {
	return codes.New(codes.ResourcesInvalid, format, args...)
}

// Preview checks staged against the settings now and says what would change.
// nodes is how many nodes the cluster has, for the replica warning. A
// refused setting is RESOURCES_INVALID and names the setting.
func Preview(cur, staged Settings, nodes int) (Plan, error) {
	var p Plan
	if staged.Replicas < 1 {
		return p, invalid("replicas: at least 1, since 0 would remove the database")
	}
	if staged.StorageBytes <= 0 {
		return p, invalid("storage: a size is needed")
	}
	if staged.StorageBytes < cur.StorageBytes {
		return p, invalid("storage: it only grows (now %s, asked for %s); a volume can't be shrunk in place", FormatSize(cur.StorageBytes), FormatSize(staged.StorageBytes))
	}
	if err := checkPools(staged.Pools); err != nil {
		return p, err
	}
	if staged.Replicas > nodes && nodes > 0 {
		p.Warnings = append(p.Warnings, fmt.Sprintf("replicas: %d is more than the %d node(s) the cluster has, so the extra replicas share a node and add no protection from losing one", staged.Replicas, nodes))
	}
	if staged.Pools.MinPoolSize > staged.Pools.DefaultPoolSize {
		p.Warnings = append(p.Warnings, fmt.Sprintf("pgbouncer.min_pool_size: %d is above default_pool_size %d, so the pool never settles at its minimum", staged.Pools.MinPoolSize, staged.Pools.DefaultPoolSize))
	}
	names := make([]string, 0, len(staged.Parameters))
	for n := range staged.Parameters {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		w, err := checkParameter(n, staged.Parameters[n])
		if err != nil {
			return p, err
		}
		if w != "" {
			p.Warnings = append(p.Warnings, w)
		}
	}

	if cur.Replicas != staged.Replicas {
		p.Changes = append(p.Changes, Change{Field: "replicas", Before: strconv.Itoa(cur.Replicas), After: strconv.Itoa(staged.Replicas)})
	}
	if cur.StorageBytes != staged.StorageBytes {
		p.Changes = append(p.Changes, Change{Field: "storage", Before: FormatSize(cur.StorageBytes), After: FormatSize(staged.StorageBytes)})
	}
	all := append(slices.Clone(names), keysNotIn(cur.Parameters, staged.Parameters)...)
	slices.Sort(all)
	for _, n := range slices.Compact(all) {
		before, had := cur.Parameters[n]
		after, has := staged.Parameters[n]
		if had == has && before == after {
			continue
		}
		p.Changes = append(p.Changes, Change{Field: "parameters." + n, Before: before, After: after, RestartRequired: needsRestart(n)})
	}
	for _, f := range poolFields(cur.Pools, staged.Pools) {
		if f.before != f.after {
			p.Changes = append(p.Changes, Change{Field: "pgbouncer." + f.name, Before: strconv.Itoa(f.before), After: strconv.Itoa(f.after)})
		}
	}
	return p, nil
}

func keysNotIn(a, b map[string]string) []string {
	var out []string
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, k)
		}
	}
	return out
}

type poolField struct {
	name          string
	before, after int
}

func poolFields(a, b Pools) []poolField {
	return []poolField{
		{"default_pool_size", a.DefaultPoolSize, b.DefaultPoolSize},
		{"min_pool_size", a.MinPoolSize, b.MinPoolSize},
		{"reserve_pool_size", a.ReservePoolSize, b.ReservePoolSize},
		{"max_client_conn", a.MaxClientConn, b.MaxClientConn},
		{"max_db_connections", a.MaxDBConns, b.MaxDBConns},
	}
}

func checkPools(p Pools) error {
	if p.DefaultPoolSize < 1 {
		return invalid("pgbouncer.default_pool_size: at least 1")
	}
	if p.MaxClientConn < 1 {
		return invalid("pgbouncer.max_client_conn: at least 1")
	}
	for _, f := range poolFields(p, p) {
		if f.after < 0 {
			return invalid("pgbouncer.%s: not negative", f.name)
		}
	}
	return nil
}

var nameRE = regexp.MustCompile(`^[a-z_][a-z0-9_]*(\.[a-z0-9_]+)?$`)

// maxValue bounds a parameter value; PostgreSQL's longest are lists of
// library names.
const maxValue = 255

// checkParameter refuses a name or value that could break the rendered
// configuration, type-checks a known parameter, and warns about an unknown
// one.
func checkParameter(name, value string) (warning string, err error) {
	if !nameRE.MatchString(name) {
		return "", invalid("parameters.%s: a parameter name is lower-case letters, digits and underscores, with at most one dot", printable(name))
	}
	if value == "" {
		return "", invalid("parameters.%s: a value is needed (remove the entry to go back to the default)", name)
	}
	if len(value) > maxValue || strings.ContainsAny(value, "\x00\r\n'\\") {
		return "", invalid("parameters.%s: the value is too long or holds a newline, quote or backslash", name)
	}
	k, known := catalog[name]
	if !known {
		return fmt.Sprintf("parameters.%s: the box doesn't know this parameter, so its value isn't checked; PostgreSQL refuses a wrong one at start", name), nil
	}
	if !k.kind.valid(value, k.enum) {
		return "", invalid("parameters.%s: %q isn't %s", name, value, k.kind.describe(k.enum))
	}
	return "", nil
}

func printable(s string) string {
	if len(s) > 40 {
		s = s[:40]
	}
	return strconv.Quote(s)
}

func needsRestart(name string) bool {
	k, ok := catalog[name]
	return ok && k.restart
}
