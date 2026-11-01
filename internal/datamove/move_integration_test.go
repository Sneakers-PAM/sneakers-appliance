// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package datamove

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// These run the move against plain PostgreSQL containers, one acting as the
// old cluster and one as the new: the same tools, the same statements and
// password logins over the network, as a box's. They need docker. Run them
// with: go test -tags integration ./internal/datamove/

const pgPassword = "invented-test-password"

var moved = []string{"app_identity", "app_vault", "app_workflow", "app_audit", "app_kratos", "app_hydra"}

func image() string {
	if v := os.Getenv("DATAMOVE_POSTGRES_IMAGE"); v != "" {
		return v
	}
	return "docker.io/library/postgres:18.6"
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput() // #nosec G204 -- test containers
	if err != nil {
		t.Fatalf("docker %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

type cluster struct {
	t    *testing.T
	name string
	spec productspec.DataCluster
}

func prefix(c productspec.DataCluster) []string { return []string{"docker", "exec", "-i", c.Name} }

// startCluster starts a container and returns it once it takes password
// logins over its network name, which is what the move connects to.
func startCluster(t *testing.T, network, name string, args ...string) *cluster {
	t.Helper()
	run := []string{"run", "-d", "--name", name, "--network", network, "-e", "POSTGRES_PASSWORD=" + pgPassword, "--tmpfs", "/var/lib/postgresql", image()}
	docker(t, append(run, args...)...)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", "-v", name).Run() }) // #nosec G204 -- only the container this test started
	c := &cluster{t: t, name: name, spec: productspec.DataCluster{
		Namespace: "test", Name: name, Host: name, User: "postgres", PasswordEnv: "POSTGRES_PASSWORD",
	}}
	return c
}

func (c *cluster) pg() *PG {
	return &PG{Shell: Exec{Prefix: prefix}, ReadyBound: 90 * time.Second, Every: 500 * time.Millisecond}
}

func (c *cluster) sql(db, q string) string {
	c.t.Helper()
	out, err := c.pg().psql(context.Background(), c.spec, db, []byte(q))
	if err != nil {
		c.t.Fatalf("%s on %s: %v", q, c.name, err)
	}
	return strings.TrimSpace(out)
}

type auditRecord struct {
	seq            uint64
	tier           int
	action, actor  string
	subject, group string
	sensitive      bool
	attrs          map[string]string
	occurred, prev string
	hash           string
}

// canonical is sneakers-audit's chain.Canonical, field for field, so a
// change there that the SQL check misses fails here.
func canonical(r auditRecord) string {
	keys := make([]string, 0, len(r.attrs))
	for k := range r.attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var attrs strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&attrs, "%s=%s;", k, r.attrs[k])
	}
	tier := map[int]string{0: "TIER_UNSPECIFIED", 1: "TIER_AUDIT", 2: "TIER_ACTIVITY"}[r.tier]
	if tier == "" {
		tier = strconv.Itoa(r.tier)
	}
	return strings.Join([]string{
		strconv.FormatUint(r.seq, 10), tier, r.action, r.actor, r.subject, r.group,
		strconv.FormatBool(r.sensitive), attrs.String(), r.occurred, r.prev,
	}, "|")
}

// chainSQL is a chain of n records, with what tripped up byte order and
// encodings: keys whose order depends on the collation, and non-ASCII.
func chainSQL(n int) string {
	var b strings.Builder
	prev := ""
	for i := 1; i <= n; i++ {
		r := auditRecord{
			seq: uint64(i), tier: i%3 + 0, action: "secret.read", actor: "user-1", subject: fmt.Sprintf("Sécret %d", i),
			group: "grp", sensitive: i%2 == 0, attrs: map[string]string{"Zeta": "1", "alpha": "two=2", "_under": "ü"},
			occurred: "2026-10-01T12:00:00.000000123Z", prev: prev,
		}
		if i%5 == 0 {
			r.attrs = map[string]string{}
		}
		sum := sha256.Sum256([]byte(canonical(r)))
		r.hash = hex.EncodeToString(sum[:])
		prev = r.hash
		js, _ := json.Marshal(r.attrs)
		fmt.Fprintf(&b, "INSERT INTO audit_records VALUES (%d, %d, %s, %s, %s, %s, %t, %s::jsonb, %s, %s, %s);\n",
			r.seq, r.tier, literal(r.action), literal(r.actor), literal(r.subject), literal(r.group), r.sensitive, literal(string(js)), literal(r.occurred), literal(r.prev), literal(r.hash))
	}
	return b.String()
}

const auditSchema = `CREATE TABLE public.audit_records (
  seq bigint PRIMARY KEY, tier integer DEFAULT 0 NOT NULL, action text NOT NULL,
  actor_user_id text DEFAULT '' NOT NULL, subject text DEFAULT '' NOT NULL, group_id text DEFAULT '' NOT NULL,
  sensitive boolean DEFAULT false NOT NULL, attributes jsonb DEFAULT '{}' NOT NULL,
  occurred_at text NOT NULL, prev_hash text DEFAULT '' NOT NULL, hash text NOT NULL
);
ALTER TABLE public.audit_records OWNER TO app;
`

func seed(t *testing.T, c *cluster) {
	t.Helper()
	c.sql("postgres", `CREATE ROLE app LOGIN PASSWORD 'invented-app-password'; CREATE ROLE reader NOLOGIN; GRANT reader TO app;`)
	for _, db := range moved {
		c.sql("postgres", fmt.Sprintf("CREATE DATABASE %s OWNER app;", db))
		c.sql(db, `SET ROLE app;
CREATE SCHEMA extra;
CREATE TABLE items (id bigserial PRIMARY KEY, label text NOT NULL, body bytea, doc jsonb, at timestamptz DEFAULT now());
CREATE TABLE extra."Odd Name" (id int PRIMARY KEY, parent bigint REFERENCES items(id));
CREATE TABLE empty_one (id int);
INSERT INTO items (label, body, doc) SELECT md5(g::text) || md5((g * 7)::text), decode(md5(g::text), 'hex'), jsonb_build_object('n', g) FROM generate_series(1, 40000) g;
INSERT INTO extra."Odd Name" SELECT g, g FROM generate_series(1, 100) g;`)
	}
	c.sql("app_audit", auditSchema+chainSQL(500))
}

// fingerprint is every table's row count and contents hash, in every moved
// database: what must be exactly the same after a failed move.
func fingerprint(c *cluster) string {
	c.t.Helper()
	var b strings.Builder
	for _, db := range moved {
		for _, tbl := range slices.Sorted(mapsKeys(c.counts(db))) {
			schema, name, _ := strings.Cut(tbl, ".")
			q := fmt.Sprintf(`SELECT count(*), md5(coalesce(string_agg(x::text, '|' ORDER BY x::text), '')) FROM %s.%s x;`, ident(schema), ident(name))
			fmt.Fprintf(&b, "%s %s %s\n", db, tbl, c.sql(db, q))
		}
	}
	return b.String()
}

func mapsKeys(m map[string]int64) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

func (c *cluster) counts(db string) map[string]int64 {
	c.t.Helper()
	m, err := c.pg().Counts(context.Background(), c.spec, db)
	if err != nil {
		c.t.Fatal(err)
	}
	return m
}

type bench struct {
	src, tgt *cluster
	before   string
	network  string
}

var (
	benchOnce sync.Once
	benchErr  error
)

func newBench(t *testing.T) *bench {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker isn't here")
	}
	name := fmt.Sprintf("datamove-test-%d-%d", os.Getpid(), time.Now().UnixNano())
	docker(t, "network", "create", name)
	t.Cleanup(func() { _ = exec.Command("docker", "network", "rm", name).Run() }) // #nosec G204 -- only the network this test made
	src := startCluster(t, name, name+"-src")
	tgt := startCluster(t, name, name+"-tgt")
	for _, c := range []*cluster{src, tgt} {
		if err := c.pg().WaitReady(context.Background(), c.spec); err != nil {
			t.Fatal(err)
		}
	}
	seed(t, src)
	return &bench{src: src, tgt: tgt, before: fingerprint(src), network: name}
}

func (b *bench) move(t *testing.T, sh Shell) (*Move, *fakeServices) {
	t.Helper()
	dir := t.TempDir()
	slot := filepath.Join(dir, "slot")
	if err := os.MkdirAll(filepath.Join(slot, "datamove"), 0o700); err != nil {
		t.Fatal(err)
	}
	q, err := os.ReadFile("../../build/product/sneakers/datamove/audit-chain.sql")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(slot, "datamove", "audit-chain.sql"), q, 0o600); err != nil {
		t.Fatal(err)
	}
	svc := &fakeServices{}
	return &Move{
		Spec: productspec.DataMove{
			Label: "Moving", After: "data", Databases: moved, Source: b.src.spec, Target: b.tgt.spec,
			Checks: []productspec.DataCheck{{Name: "the audit chain", Database: "app_audit", File: "datamove/audit-chain.sql"}},
		},
		Slot: slot, BackupDir: filepath.Join(dir, "backup"), Journal: filepath.Join(dir, "data-move.json"), Volumes: dir,
		Engine:   &PG{Shell: sh, ReadyBound: 20 * time.Second, Every: 500 * time.Millisecond},
		Services: svc,
		Disk:     func(string) (Usage, error) { return Usage{Avail: 1 << 40, Device: 1}, nil },
	}, svc
}

// clearTarget puts the new cluster back to empty between tests.
func (b *bench) clearTarget(t *testing.T) {
	t.Helper()
	for _, db := range moved {
		b.tgt.sql("postgres", "DROP DATABASE IF EXISTS "+db+" WITH (FORCE);")
	}
	b.tgt.sql("postgres", "DROP ROLE IF EXISTS app; DROP ROLE IF EXISTS reader;")
}

// oldDataIsBack is what every failure must end in: the old cluster holds
// exactly what it held, and still takes writes.
func (b *bench) oldDataIsBack(t *testing.T, svc *fakeServices) {
	t.Helper()
	if got := fingerprint(b.src); got != b.before {
		t.Fatalf("the old cluster changed:\n%s\nwas:\n%s", got, b.before)
	}
	b.src.sql("app_identity", "BEGIN; INSERT INTO items (label) VALUES ('probe'); ROLLBACK;")
	if slices.Contains(svc.calls, "start") {
		t.Fatal("the services started on a failed move")
	}
}

func execShell() Exec { return Exec{Prefix: prefix} }

func TestMoveAgainstPlainPostgres(t *testing.T) {
	b := newBench(t)

	t.Run("it moves every table and role", func(t *testing.T) {
		b.clearTarget(t)
		m, svc := b.move(t, execShell())
		if err := m.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(svc.calls, []string{"stop", "start"}) {
			t.Fatalf("services %v", svc.calls)
		}
		if got := fingerprint(b.tgt); got != b.before {
			t.Fatalf("the target differs:\n%s\nsource:\n%s", got, b.before)
		}
		if got := fingerprint(b.src); got != b.before {
			t.Fatal("the source changed")
		}
		if got := b.tgt.sql("postgres", "SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid WHERE r.rolname = 'reader';"); got != "1" {
			t.Fatalf("role membership: %s", got)
		}
		if got := b.tgt.sql("app_vault", "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database();"); got != "app" {
			t.Fatalf("owner %s", got)
		}
		src := "SELECT datcollate || datctype FROM pg_database WHERE datname = 'app_vault';"
		if b.src.sql("postgres", src) != b.tgt.sql("postgres", src) {
			t.Fatal("the locale changed")
		}
		if got, want := b.tgt.sql("app_vault", "SELECT nextval('items_id_seq');"), "40001"; got != want {
			t.Fatalf("the sequence is at %s", got)
		}
		if out, err := appLogin(b.tgt.name); err != nil {
			t.Fatalf("the app role can't sign in with its old password: %v: %s", err, out)
		}
		if err := m.Settle(); err != nil {
			t.Fatal(err)
		}
		if err := m.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a role the new cluster has keeps its password", func(t *testing.T) {
		b.clearTarget(t)
		// Same password, another salt: the dump's verifier isn't this one.
		q := "SELECT rolpassword FROM pg_authid WHERE rolname = 'postgres';"
		before := b.tgt.sql("postgres", q)
		if before == b.src.sql("postgres", q) {
			t.Fatal("the clusters share a verifier, so this proves nothing")
		}
		m, _ := b.move(t, execShell())
		if err := m.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		if b.tgt.sql("postgres", q) != before {
			t.Fatal("the dump changed the new cluster's own role")
		}
	})

	t.Run("the audit check finds a broken chain", func(t *testing.T) {
		b.clearTarget(t)
		const seq = "250"
		tamper := func(on string) {
			b.src.sql("app_audit", "UPDATE audit_records SET subject = subject || "+literal(on)+" WHERE seq = "+seq+";")
		}
		tamper("x")
		t.Cleanup(func() {
			b.src.sql("app_audit", "UPDATE audit_records SET subject = left(subject, length(subject) - 1) WHERE seq = "+seq+";")
		})
		m, _ := b.move(t, execShell())
		err := m.Run(context.Background())
		if !codes.Is(err, codes.DataMove) || !strings.Contains(err.Error(), "broken at seq "+seq) {
			t.Fatalf("%v", err)
		}
	})

	t.Run("the audit check finds a missing record", func(t *testing.T) {
		b.clearTarget(t)
		row := b.src.sql("app_audit", "SELECT count(*) FROM audit_records;")
		b.src.sql("app_audit", "CREATE TABLE keep AS SELECT * FROM audit_records WHERE seq = 300; DELETE FROM audit_records WHERE seq = 300;")
		t.Cleanup(func() {
			b.src.sql("app_audit", "INSERT INTO audit_records SELECT * FROM keep; DROP TABLE keep;")
			if got := b.src.sql("app_audit", "SELECT count(*) FROM audit_records;"); got != row {
				t.Errorf("the fixture wasn't put back: %s", got)
			}
		})
		m, _ := b.move(t, execShell())
		err := m.Run(context.Background())
		if !codes.Is(err, codes.DataMove) || !strings.Contains(err.Error(), "broken at seq 301") {
			t.Fatalf("%v", err)
		}
	})

	t.Run("a target that holds other data is left alone", func(t *testing.T) {
		b.clearTarget(t)
		b.tgt.sql("postgres", "CREATE DATABASE app_hydra;")
		b.tgt.sql("app_hydra", "CREATE TABLE theirs (id int); INSERT INTO theirs VALUES (1);")
		m, svc := b.move(t, execShell())
		err := m.Run(context.Background())
		if !codes.Is(err, codes.DataMove) || !strings.Contains(err.Error(), "app_hydra") {
			t.Fatalf("%v", err)
		}
		if got := b.tgt.sql("app_hydra", "SELECT count(*) FROM theirs;"); got != "1" {
			t.Fatalf("their row: %s", got)
		}
		b.oldDataIsBack(t, svc)
	})

	t.Run("a target the chart made empty is filled", func(t *testing.T) {
		b.clearTarget(t)
		b.tgt.sql("postgres", "CREATE DATABASE app_hydra;")
		m, _ := b.move(t, execShell())
		if err := m.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("the failure paths", func(t *testing.T) { failurePaths(t, b) })
}

func appLogin(name string) (string, error) {
	cmd := exec.Command("docker", "exec", "-e", "PGPASSWORD=invented-app-password", name, "psql", "-h", name, "-U", "app", "-d", "app_vault", "-c", "SELECT count(*) FROM items;") // #nosec G204 -- test containers
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// killer is a Shell that kills the named tool with SIGKILL, in its own
// container, once it's really mid-stream: the stream is held until the kill
// went in, so the tool can't get to the end first.
type killer struct {
	Exec
	t    *testing.T
	tool string
	db   string
	once sync.Once
	hit  bool
}

func (k *killer) kill(c productspec.DataCluster) {
	k.once.Do(func() {
		k.hit = true
		script := `for p in /proc/[0-9]*; do [ "$(cat "$p/comm" 2>/dev/null)" = "` + k.tool + `" ] && kill -9 "${p#/proc/}"; done; true`
		out, err := exec.Command("docker", "exec", c.Name, "sh", "-c", script).CombinedOutput() // #nosec G204 -- test containers
		if err != nil {
			k.t.Errorf("kill: %v: %s", err, out)
		}
	})
}

type killWriter struct {
	w io.Writer
	k *killer
	c productspec.DataCluster
}

func (w killWriter) Write(b []byte) (int, error) {
	w.k.kill(w.c)
	return w.w.Write(b)
}

type killReader struct {
	r io.Reader
	k *killer
	c productspec.DataCluster
	n int
}

func (r *killReader) Read(b []byte) (int, error) {
	if r.n > 16<<10 {
		r.k.kill(r.c)
	}
	n, err := r.r.Read(b)
	r.n += n
	return n, err
}

func (k *killer) Run(ctx context.Context, c productspec.DataCluster, argv []string, in io.Reader, out io.Writer) error {
	match := argv[0] == k.tool && (k.db == "" || slices.ContainsFunc(argv, func(a string) bool { return strings.HasSuffix(a, "="+k.db) }))
	if !match {
		return k.Exec.Run(ctx, c, argv, in, out)
	}
	if in != nil {
		return k.Exec.Run(ctx, c, argv, &killReader{r: in, k: k, c: c}, out)
	}
	return k.Exec.Run(ctx, c, argv, in, killWriter{w: out, k: k, c: c})
}

// lateFail fails from the n-th psql on the target: the target going away
// after the data is in, before the switch.
type lateFail struct {
	Exec
	match func(argv []string, in []byte) bool
	hit   bool
}

func (l *lateFail) Run(ctx context.Context, c productspec.DataCluster, argv []string, in io.Reader, out io.Writer) error {
	if in != nil && argv[0] == "psql" {
		b, err := io.ReadAll(in)
		if err != nil {
			return err
		}
		if l.match(argv, b) {
			l.hit = true
			return errors.New("the target went away")
		}
		in = bytes.NewReader(b)
	}
	return l.Exec.Run(ctx, c, argv, in, out)
}

func failurePaths(t *testing.T, b *bench) {
	cases := map[string]struct {
		shell func(t *testing.T) (Shell, func() bool)
	}{
		"killed mid-dump": {func(t *testing.T) (Shell, func() bool) {
			k := &killer{Exec: execShell(), t: t, tool: "pg_dump", db: "app_vault"}
			return k, func() bool { return k.hit }
		}},
		"killed mid-restore": {func(t *testing.T) (Shell, func() bool) {
			k := &killer{Exec: execShell(), t: t, tool: "pg_restore"}
			return k, func() bool { return k.hit }
		}},
		"killed before the switch": {func(t *testing.T) (Shell, func() bool) {
			l := &lateFail{Exec: execShell(), match: func(_ []string, q []byte) bool { return bytes.Contains(q, []byte("walked")) }}
			return l, func() bool { return l.hit }
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			b.clearTarget(t)
			sh, hit := c.shell(t)
			m, svc := b.move(t, sh)
			err := m.Run(context.Background())
			if !hit() {
				t.Fatal("the failure never happened")
			}
			if !codes.Is(err, codes.DataMove) {
				t.Fatalf("%v", err)
			}
			if j, _ := m.Read(); j.State != StateFailed {
				t.Fatalf("%+v", j)
			}
			b.oldDataIsBack(t, svc)

			// The next apply moves the data after all, over what the
			// failed attempt left behind.
			m.Engine = &PG{Shell: execShell(), ReadyBound: 20 * time.Second, Every: 500 * time.Millisecond}
			if err := m.Run(context.Background()); err != nil {
				t.Fatal(err)
			}
			if got := fingerprint(b.tgt); got != b.before {
				t.Fatal("the second attempt's target differs")
			}
		})
	}

	for _, at := range []string{"dump", "restore", "switch"} {
		t.Run("the box dies at "+at, func(t *testing.T) { boxDies(t, b, at) })
	}
}

// boxDies runs the move in a process of its own and SIGKILLs that process
// at the point named: no deferred work and no error path runs, as in a power
// loss. A new run finds the journal and goes back.
func boxDies(t *testing.T, b *bench, at string) {
	b.clearTarget(t)
	m, svc := b.move(t, execShell())
	cfg, err := json.Marshal(helperConfig{Spec: m.Spec, Slot: m.Slot, BackupDir: m.BackupDir, Journal: m.Journal, Volumes: m.Volumes, At: at})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestHelperMoveThatDies$") // #nosec G204 -- this test binary
	cmd.Env = append(os.Environ(), "DATAMOVE_HELPER="+string(cfg))
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("the helper wasn't killed: %v: %s", err, out)
	}
	j, rerr := m.Read()
	if rerr != nil {
		t.Fatal(rerr)
	}
	if j.State != StateRunning {
		t.Fatalf("the journal says %+v", j)
	}
	err = m.Run(context.Background())
	if !errors.Is(err, ErrInterrupted) {
		t.Fatalf("%v", err)
	}
	b.oldDataIsBack(t, svc)
	if err := m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := fingerprint(b.tgt); got != b.before {
		t.Fatal("the attempt after the crash differs")
	}
}

type helperConfig struct {
	Spec                              productspec.DataMove
	Slot, BackupDir, Journal, Volumes string
	At                                string
}

// dying is a Shell whose process dies at a tool, mid-stream.
type dying struct {
	Exec
	at string
}

type dieWriter struct{ w io.Writer }

func (d dieWriter) Write(b []byte) (int, error) {
	_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
	time.Sleep(time.Minute)
	return d.w.Write(b)
}

type dieReader struct {
	r io.Reader
	n int
}

func (d *dieReader) Read(b []byte) (int, error) {
	if d.n > 16<<10 {
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		time.Sleep(time.Minute)
	}
	n, err := d.r.Read(b)
	d.n += n
	return n, err
}

func (d dying) Run(ctx context.Context, c productspec.DataCluster, argv []string, in io.Reader, out io.Writer) error {
	switch {
	case d.at == "dump" && argv[0] == "pg_dump" && slices.Contains(argv, "--dbname=app_workflow"):
		out = dieWriter{out}
	case d.at == "restore" && argv[0] == "pg_restore":
		in = &dieReader{r: in}
	case d.at == "switch" && in != nil && argv[0] == "psql":
		q, err := io.ReadAll(in)
		if err != nil {
			return err
		}
		if bytes.Contains(q, []byte("walked")) {
			if err := d.Exec.Run(ctx, c, argv, bytes.NewReader(q), out); err != nil {
				return err
			}
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			time.Sleep(time.Minute)
		}
		in = bytes.NewReader(q)
	}
	return d.Exec.Run(ctx, c, argv, in, out)
}

func TestHelperMoveThatDies(t *testing.T) {
	raw := os.Getenv("DATAMOVE_HELPER")
	if raw == "" {
		t.Skip("runs only as boxDies's helper")
	}
	var cfg helperConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	m := &Move{
		Spec: cfg.Spec, Slot: cfg.Slot, BackupDir: cfg.BackupDir, Journal: cfg.Journal, Volumes: cfg.Volumes,
		Engine:   &PG{Shell: dying{Exec: execShell(), at: cfg.At}, ReadyBound: 20 * time.Second, Every: 500 * time.Millisecond},
		Services: &fakeServices{},
		Disk:     func(string) (Usage, error) { return Usage{Avail: 1 << 40, Device: 1}, nil },
	}
	t.Fatalf("the move ended: %v", m.Run(context.Background()))
}

func TestTheTLSModeIsHonoured(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker isn't here")
	}
	name := fmt.Sprintf("datamove-tls-%d-%d", os.Getpid(), time.Now().UnixNano())
	docker(t, "network", "create", name)
	t.Cleanup(func() { _ = exec.Command("docker", "network", "rm", name).Run() }) // #nosec G204 -- only the network this test made
	plain := startCluster(t, name, name+"-plain")
	tls := startCluster(t, name, name+"-tls")
	for _, c := range []*cluster{plain, tls} {
		if err := c.pg().WaitReady(context.Background(), c.spec); err != nil {
			t.Fatal(err)
		}
	}
	// A throwaway self-signed certificate, made in the container.
	docker(t, "exec", tls.name, "sh", "-c", `cd /var/lib/postgresql && openssl req -new -x509 -days 1 -nodes -subj /CN=target -out s.crt -keyout s.key 2>/dev/null && chmod 600 s.key && chown postgres s.crt s.key`)
	tls.sql("postgres", `ALTER SYSTEM SET ssl = on; ALTER SYSTEM SET ssl_cert_file = '/var/lib/postgresql/s.crt'; ALTER SYSTEM SET ssl_key_file = '/var/lib/postgresql/s.key';`)
	tls.sql("postgres", "SELECT pg_reload_conf();")

	t.Run("sslmode=require runs over TLS", func(t *testing.T) {
		c := tls.spec
		c.SSLMode = "require"
		pg := tls.pg()
		var out string
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			var err error
			if out, err = pg.Check(context.Background(), c, "postgres", []byte("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid();")); err == nil {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if strings.TrimSpace(out) != "t" {
			t.Fatalf("ssl=%q", out)
		}
	})

	t.Run("sslmode=require against a plain server fails the move", func(t *testing.T) {
		c := plain.spec
		c.SSLMode = "require"
		pg := plain.pg()
		pg.ReadyBound = 2 * time.Second
		err := pg.WaitReady(context.Background(), c)
		if err == nil || !strings.Contains(err.Error(), "SSL") {
			t.Fatalf("%v", err)
		}
	})

	t.Run("a dropped password is refused, not skipped", func(t *testing.T) {
		c := tls.spec
		c.PasswordEnv = "NOT_SET_HERE"
		pg := tls.pg()
		pg.ReadyBound = time.Second
		if err := pg.WaitReady(context.Background(), c); err == nil {
			t.Fatal("connected with no password")
		}
	})
}
