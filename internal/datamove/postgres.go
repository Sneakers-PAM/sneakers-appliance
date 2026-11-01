// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package datamove

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// Shell runs a PostgreSQL client program where a cluster's tools are. Exec
// is the one everything uses; tests point it at a plain container.
type Shell interface {
	Run(ctx context.Context, c productspec.DataCluster, argv []string, in io.Reader, out io.Writer) error
}

// maintenanceDB is the database to connect to when none is the point.
const maintenanceDB = "postgres"

// defaultReadyBound is how long a cluster gets to take a connection.
const defaultReadyBound = 5 * time.Minute

// PG is the box's Engine: PostgreSQL's own client tools, through a Shell.
type PG struct {
	Shell Shell
	// ReadyBound is how long WaitReady waits; 0 is 5 minutes.
	ReadyBound time.Duration
	// Every is how often WaitReady asks; 0 is 2 seconds.
	Every  time.Duration
	Logger log.Logger
}

func (p *PG) logger() log.Logger {
	if p.Logger == nil {
		return log.Nop()
	}
	return p.Logger
}

func ident(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

func literal(s string) string { return `'` + strings.ReplaceAll(s, `'`, `''`) + `'` }

// psql runs sql from its standard input, stopping at the first error, with
// the plain output a program reads.
func (p *PG) psql(ctx context.Context, c productspec.DataCluster, db string, sql []byte) (string, error) {
	var out bytes.Buffer
	err := p.Shell.Run(ctx, c, []string{"psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-F", "\t", "-d", db, "-f", "-"}, bytes.NewReader(sql), &out)
	return out.String(), err
}

// WaitReady waits until the cluster answers a query over the declared
// host and TLS mode, so a target that can't do TLS fails here.
func (p *PG) WaitReady(ctx context.Context, c productspec.DataCluster) error {
	bound, every := p.ReadyBound, p.Every
	if bound <= 0 {
		bound = defaultReadyBound
	}
	if every <= 0 {
		every = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	start := time.Now()
	for {
		_, err := p.psql(ctx, c, maintenanceDB, []byte("SELECT 1;"))
		if err == nil {
			p.logger().Debug("datamove: the cluster answers", log.F("cluster", c.Name), log.F("seconds", int(time.Since(start).Seconds())))
			return nil
		}
		p.logger().Debug("datamove: waiting for the cluster", log.F("cluster", c.Name), log.F("error", err.Error()))
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s doesn't answer: %w", c.Name, err)
		case <-time.After(every):
		}
	}
}

// Size implements Engine.
func (p *PG) Size(ctx context.Context, c productspec.DataCluster, dbs []string) (int64, error) {
	lits := make([]string, len(dbs))
	for i, db := range dbs {
		lits[i] = literal(db)
	}
	q := "SELECT coalesce(sum(pg_database_size(datname)), 0)::bigint FROM pg_database WHERE datname IN (" + strings.Join(lits, ",") + ");"
	out, err := p.psql(ctx, c, maintenanceDB, []byte(q))
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("the size of the databases: %w", err)
	}
	return n, nil
}

func (p *PG) exists(ctx context.Context, c productspec.DataCluster, db string) (bool, error) {
	out, err := p.psql(ctx, c, maintenanceDB, []byte("SELECT count(*) FROM pg_database WHERE datname = "+literal(db)+";"))
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) == "1", nil
}

const userTables = `pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema') AND schemaname NOT LIKE 'pg\_%'`

// Tables implements Engine.
func (p *PG) Tables(ctx context.Context, c productspec.DataCluster, db string) (int, error) {
	ok, err := p.exists(ctx, c, db)
	if err != nil || !ok {
		return 0, err
	}
	out, err := p.psql(ctx, c, db, []byte("SELECT count(*) FROM "+userTables+";"))
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return 0, fmt.Errorf("the tables of %s: %w", db, err)
	}
	return n, nil
}

// DumpRoles implements Engine. The output holds password verifiers.
func (p *PG) DumpRoles(ctx context.Context, c productspec.DataCluster, w io.Writer) error {
	return p.Shell.Run(ctx, c, []string{"pg_dumpall", "--roles-only"}, nil, w)
}

// DumpDatabase implements Engine.
func (p *PG) DumpDatabase(ctx context.Context, c productspec.DataCluster, db string, w io.Writer) error {
	return p.Shell.Run(ctx, c, []string{"pg_dump", "--format=custom", "--dbname=" + db}, nil, w)
}

var roleLine = regexp.MustCompile(`^(?:CREATE|ALTER) ROLE ("(?:[^"]|"")+"|[^\s;]+)`)

// keepRoles drops the lines that would change a role the target already
// has: its chart made them, and the passwords it holds are the ones it
// connects with. Every other line of the dump is kept.
func keepRoles(sql []byte, have map[string]bool) []byte {
	var out bytes.Buffer
	for line := range bytes.Lines(sql) {
		if m := roleLine.FindSubmatch(line); m != nil {
			name := string(m[1])
			if strings.HasPrefix(name, `"`) {
				name = strings.ReplaceAll(name[1:len(name)-1], `""`, `"`)
			}
			if have[name] {
				continue
			}
		}
		out.Write(line)
	}
	return out.Bytes()
}

// RestoreRoles implements Engine.
func (p *PG) RestoreRoles(ctx context.Context, c productspec.DataCluster, r io.Reader) error {
	sql, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	out, err := p.psql(ctx, c, maintenanceDB, []byte("SELECT rolname FROM pg_roles;"))
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for line := range strings.Lines(out) {
		have[strings.TrimSpace(line)] = true
	}
	p.logger().Debug("datamove: the target's own roles stay as they are", log.F("roles", len(have)))
	// The statements carry password verifiers, so psql's output, which
	// could echo one, goes nowhere.
	return p.Shell.Run(ctx, c, []string{"psql", "-X", "-q", "-o", "/dev/null", "-v", "ON_ERROR_STOP=1", "-d", maintenanceDB, "-f", "-"}, bytes.NewReader(keepRoles(sql, have)), io.Discard)
}

// DropDatabase implements Engine.
func (p *PG) DropDatabase(ctx context.Context, c productspec.DataCluster, db string) error {
	_, err := p.psql(ctx, c, maintenanceDB, []byte("DROP DATABASE IF EXISTS "+ident(db)+" WITH (FORCE);"))
	return err
}

// RestoreDatabase implements Engine. --create brings the database's own
// owner, locale and grants from the dump.
func (p *PG) RestoreDatabase(ctx context.Context, c productspec.DataCluster, _ string, r io.Reader) error {
	return p.Shell.Run(ctx, c, []string{"pg_restore", "--create", "--exit-on-error", "--dbname=" + maintenanceDB}, r, io.Discard)
}

// Counts implements Engine. It reads every table once, in one statement,
// so a large table costs one scan; with the services stopped nothing
// moves under it.
func (p *PG) Counts(ctx context.Context, c productspec.DataCluster, db string) (map[string]int64, error) {
	list := "SELECT string_agg(format('SELECT %L, count(*) FROM %I.%I', schemaname || '.' || tablename, schemaname, tablename), ' UNION ALL ') FROM " + userTables + ";"
	q, err := p.psql(ctx, c, db, []byte(list))
	if err != nil {
		return nil, err
	}
	rows := map[string]int64{}
	q = strings.TrimSpace(q)
	if q == "" {
		return rows, nil
	}
	out, err := p.psql(ctx, c, db, []byte(q+";"))
	if err != nil {
		return nil, err
	}
	for line := range strings.Lines(out) {
		name, n, ok := strings.Cut(strings.TrimRight(line, "\n"), "\t")
		if !ok {
			return nil, fmt.Errorf("counting %s: a line that isn't a count", db)
		}
		v, err := strconv.ParseInt(n, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("counting %s: %w", db, err)
		}
		rows[name] = v
	}
	return rows, nil
}

// Check implements Engine.
func (p *PG) Check(ctx context.Context, c productspec.DataCluster, db string, query []byte) (string, error) {
	return p.psql(ctx, c, db, query)
}

// ErrNoTool is a client program the pod doesn't have.
var ErrNoTool = errors.New("the tool isn't in the pod")
