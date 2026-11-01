// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package datamove

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

func TestKeepRolesLeavesTheTargetsOwnRolesAlone(t *testing.T) {
	dump := `\restrict abc
SET default_transaction_read_only = off;
CREATE ROLE postgres;
ALTER ROLE postgres WITH SUPERUSER LOGIN PASSWORD 'SCRAM-SHA-256$old';
CREATE ROLE app;
ALTER ROLE app WITH LOGIN PASSWORD 'SCRAM-SHA-256$app';
CREATE ROLE "odd""name";
ALTER ROLE "odd""name" WITH NOLOGIN;
ALTER ROLE app SET search_path TO public;
GRANT app TO reader GRANTED BY postgres;
\unrestrict abc
`
	got := string(keepRoles([]byte(dump), map[string]bool{"postgres": true, `odd"name`: true}))
	for _, gone := range []string{"CREATE ROLE postgres", "$old", "odd"} {
		if strings.Contains(got, gone) {
			t.Errorf("%q stayed:\n%s", gone, got)
		}
	}
	for _, kept := range []string{`\restrict abc`, "CREATE ROLE app;", "$app", "SET search_path", "GRANT app TO reader", `\unrestrict abc`} {
		if !strings.Contains(got, kept) {
			t.Errorf("%q went:\n%s", kept, got)
		}
	}
}

func TestScrubKeepsTheErrorAndNoData(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"restore": {
			"pg_restore: error: COPY failed for table \"t\": ERROR:  invalid input CONTEXT:  COPY t, line 3: \"a-secret-value\"\n",
			"pg_restore: error: COPY failed for table \"t\": ERROR:  invalid input",
		},
		"multi line": {
			"pg_restore: creating TABLE\npsql:<stdin>:4: ERROR:  duplicate key\nDETAIL:  Key (id)=(a-secret-value) already exists.\n",
			"psql:<stdin>:4: ERROR:  duplicate key",
		},
		"detail on the line": {
			"ERROR:  duplicate DETAIL: Key (id)=(a-secret-value)\n",
			"ERROR:  duplicate",
		},
		"no error word": {"could not connect to server\n", "could not connect to server"},
		"empty":         {"", ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got := Scrub(c.in)
			if got != c.want {
				t.Fatalf("got %q", got)
			}
			if strings.Contains(got, "a-secret-value") {
				t.Fatal("a value got through")
			}
		})
	}
	if long := Scrub(strings.Repeat("x", 5000)); len(long) != errorBytes {
		t.Fatalf("%d bytes", len(long))
	}
}

func TestExecPutsThePasswordInThePodAndNotOnTheCommandLine(t *testing.T) {
	e := Exec{Prefix: func(c productspec.DataCluster) []string { return []string{"kubectl", "exec", c.Name + "-0", "--"} }}
	c := productspec.DataCluster{Name: "db", Host: "db.svc", User: "postgres", SSLMode: "verify-full", SSLRootCert: "/tls/ca.crt", PasswordEnv: "POSTGRES_PASSWORD"}
	got := e.Argv(c, []string{"psql", "-d", "x"})
	want := []string{
		"kubectl", "exec", "db-0", "--", "sh", "-c", `PGPASSWORD="$POSTGRES_PASSWORD" exec "$@"`, "sh",
		"env", "PGHOST=db.svc", "PGPORT=5432", "PGUSER=postgres", "PGSSLMODE=verify-full", "PGSSLROOTCERT=/tls/ca.crt", "psql", "-d", "x",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
	c.PasswordEnv = ""
	if g := e.Argv(c, nil); g[6] != `exec "$@"` {
		t.Fatalf("%q", g[6])
	}
}

func TestKubePrefixExecsIntoTheFirstPodWithItsInputOpen(t *testing.T) {
	got := KubePrefix("/slot/k0s", "/pki/admin.conf")(productspec.DataCluster{Namespace: "app", Name: "new-db"})
	want := []string{"/slot/k0s", "kubectl", "--kubeconfig", "/pki/admin.conf", "exec", "-i", "--namespace", "app", "new-db-0", "--container", "postgres", "--"}
	if !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
}

func TestExecNamesAToolThatIsNotThere(t *testing.T) {
	e := Exec{Prefix: func(productspec.DataCluster) []string { return nil }}
	err := e.Run(context.Background(), productspec.DataCluster{Host: "h", User: "u"}, []string{"no-such-tool-here"}, nil, nil)
	if !errors.Is(err, ErrNoTool) {
		t.Fatalf("%v", err)
	}
}
