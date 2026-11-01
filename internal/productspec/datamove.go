// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productspec

import (
	"regexp"
	"slices"
	"time"
)

// DefaultDataMoveTimeout is how long a data move may take when product.yaml
// names no timeout. It's a guard against a move that hangs, not a limit on
// a large database: a move takes the product offline for as long as it
// runs, once on a box.
const DefaultDataMoveTimeout = 6 * time.Hour

// The bounds of a data move's timeout.
const (
	minDataMoveTimeout = time.Minute
	maxDataMoveTimeout = 24 * time.Hour
)

// DataMove is a one-time move of the product's databases from the cluster
// in Source to the new cluster in Target (docs/data-move.md). Both are
// workloads of the phase After. The product holds the phases after it
// until the move is through; a move that fails returns the box to the
// previous product slot. The appliance knows no chart: everything it
// needs is named here.
type DataMove struct {
	// Label is the step's words in Updates, the console and the box-state
	// stream.
	Label string `yaml:"label"`
	// After is the phase whose workloads include both clusters.
	After string `yaml:"after"`
	// Databases are moved with the roles of the source cluster.
	Databases []string    `yaml:"databases"`
	Source    DataCluster `yaml:"source"`
	Target    DataCluster `yaml:"target"`
	// Checks run on the target after every table's row count matched.
	Checks []DataCheck `yaml:"checks"`
	// Timeout bounds the whole move; empty is DefaultDataMoveTimeout.
	Timeout string `yaml:"timeout"`
}

// DataCluster is one PostgreSQL cluster of a data move. The box runs the
// client tools inside the cluster's first pod (<Name>-0), so the images
// supply them and no password leaves the pod.
type DataCluster struct {
	Namespace string `yaml:"namespace"`
	// Name is the StatefulSet.
	Name string `yaml:"name"`
	// Container is the pod's PostgreSQL container; empty is "postgres".
	Container string `yaml:"container"`
	// Host is what the tools connect to, from inside the pod.
	Host string `yaml:"host"`
	// Port is empty for 5432.
	Port int `yaml:"port"`
	// SSLMode is the libpq sslmode; empty is "disable".
	SSLMode string `yaml:"sslmode"`
	// SSLRootCert is a path inside the pod, for the verify modes.
	SSLRootCert string `yaml:"ssl_root_cert"`
	// User is a superuser.
	User string `yaml:"user"`
	// PasswordEnv names the environment variable of the pod that holds
	// User's password; the box never reads it. Empty uses none.
	PasswordEnv string `yaml:"password_env"`
}

// DataCheck is a query the bundle carries that checks the moved data. It
// runs as a superuser on the target and prints exactly "ok" when the data
// is sound; anything else fails the move, and is shown, so it must print
// only what's safe to log.
type DataCheck struct {
	Name     string `yaml:"name"`
	Database string `yaml:"database"`
	// File is relative to the slot.
	File string `yaml:"file"`
}

// PortOrDefault is the cluster's port.
func (c DataCluster) PortOrDefault() int {
	if c.Port == 0 {
		return 5432
	}
	return c.Port
}

// SSLModeOrDefault is the cluster's sslmode.
func (c DataCluster) SSLModeOrDefault() string {
	if c.SSLMode == "" {
		return "disable"
	}
	return c.SSLMode
}

// ContainerOrDefault is the pod's PostgreSQL container.
func (c DataCluster) ContainerOrDefault() string {
	if c.Container == "" {
		return "postgres"
	}
	return c.Container
}

// TimeoutOrDefault is the move's timeout.
func (m DataMove) TimeoutOrDefault() time.Duration {
	if m.Timeout == "" {
		return DefaultDataMoveTimeout
	}
	d, _ := time.ParseDuration(m.Timeout)
	return d
}

// DataMoveLater are the phases that wait for the data move.
func (s Spec) DataMoveLater() []Phase {
	if s.DataMove == nil {
		return nil
	}
	for i, p := range s.Phases {
		if p.Name == s.DataMove.After {
			return s.Phases[i+1:]
		}
	}
	return nil
}

var (
	dbNameRE   = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
	dnsNameRE  = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)
	envNameRE  = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	roleNameRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,62}$`)
	sqlFileRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*\.sql$`)
	inPodPath  = regexp.MustCompile(`^(/[a-zA-Z0-9._-]+)+$`)
	sslModes   = []string{"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}
)

func (s Spec) checkDataMove() error {
	m := s.DataMove
	if m == nil {
		return nil
	}
	if m.Label == "" {
		return bad("data_move: a label is required")
	}
	if len(s.DataMoveLater()) == 0 {
		return bad("data_move: after %q isn't a phase with later phases", m.After)
	}
	if len(m.Databases) == 0 {
		return bad("data_move: no databases")
	}
	seen := map[string]bool{}
	for _, db := range m.Databases {
		if !dbNameRE.MatchString(db) || seen[db] {
			return bad("data_move: database %q is invalid or named twice", db)
		}
		seen[db] = true
	}
	if m.Source.Name == m.Target.Name {
		return bad("data_move: the target needs its own name; taking over the source's volume would damage the way back")
	}
	for _, c := range []struct {
		role string
		c    DataCluster
	}{{"source", m.Source}, {"target", m.Target}} {
		if err := checkDataCluster(s, m.After, c.role, c.c); err != nil {
			return err
		}
	}
	for _, c := range m.Checks {
		if c.Name == "" || !seen[c.Database] || !sqlFileRE.MatchString(c.File) {
			return bad("data_move: check %q needs a name, one of the moved databases and a .sql file in the slot", c.Name)
		}
	}
	if m.Timeout != "" {
		d, err := time.ParseDuration(m.Timeout)
		if err != nil || d < minDataMoveTimeout || d > maxDataMoveTimeout {
			return bad("data_move: timeout %q isn't between %s and %s", m.Timeout, minDataMoveTimeout, maxDataMoveTimeout)
		}
	}
	return nil
}

func checkDataCluster(s Spec, after, role string, c DataCluster) error {
	i, ok := s.PhaseOf(c.Name)
	if !ok || s.Phases[i].Name != after {
		return bad("data_move: the %s %q isn't a workload of the phase %q", role, c.Name, after)
	}
	if !dnsNameRE.MatchString(c.Namespace) || !dnsNameRE.MatchString(c.Host) {
		return bad("data_move: the %s needs a namespace and a host", role)
	}
	if c.Port < 0 || c.Port > 65535 {
		return bad("data_move: the %s's port %d is out of range", role, c.Port)
	}
	if !slices.Contains(sslModes, c.SSLModeOrDefault()) {
		return bad("data_move: the %s's sslmode %q isn't one libpq knows", role, c.SSLMode)
	}
	if !roleNameRE.MatchString(c.User) {
		return bad("data_move: the %s needs a user", role)
	}
	if c.PasswordEnv != "" && !envNameRE.MatchString(c.PasswordEnv) {
		return bad("data_move: the %s's password_env isn't an environment variable's name", role)
	}
	if c.SSLRootCert != "" && !inPodPath.MatchString(c.SSLRootCert) {
		return bad("data_move: the %s's ssl_root_cert isn't an absolute path", role)
	}
	if !dnsNameRE.MatchString(c.ContainerOrDefault()) {
		return bad("data_move: the %s's container is invalid", role)
	}
	return nil
}
