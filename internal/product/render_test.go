// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package product_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/product"
)

const renderRelease = `apiVersion: sneakers-pam/v1alpha1
kind: Release
spec:
  services:
    gateway:
      image: ghcr.io/sneakers-pam/sneakers-gateway
      digest: sha256:1111111111111111111111111111111111111111111111111111111111111111
  thirdParty:
    postgres:
      image: docker.io/library/postgres
      digest: sha256:3333333333333333333333333333333333333333333333333333333333333333
    postgres-ha:
      image: docker.io/library/postgres-ha
      digest: sha256:5555555555555555555555555555555555555555555555555555555555555555
      chart:
        name: postgres-ha
        version: 1.0.2
        repository: oci://registry.example.org/charts
        digest: sha256:4444444444444444444444444444444444444444444444444444444444444444
`

const renderProduct = `format: 2
box_secrets:
  - secret: sneakers/sneakers-bundled
    keys: [{key: password, generate: password}]
phases:
  - {name: data, label: The database, stack: sneakers-data, workloads: [sneakers-pgha]}
  - {name: front, label: The gateway, stack: sneakers-front, workloads: [sneakers-gateway]}
resources:
  chart: postgres-ha
  phase: data
  release: sneakers-pgha
  namespace: sneakers
  data: /var/lib/sneakers-data
  values:
    fullnameOverride: sneakers-pgha
    postgresql:
      parameters:
        max_connections: 100
`

const renderOut = `apiVersion: v1
kind: Service
metadata: {name: sneakers-pgha-primary}
spec: {ports: [{port: 5432}]}
---
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: sneakers-pgha}
spec:
  template:
    spec:
      securityContext: {runAsUser: 999}
      containers:
        - name: postgres
          image: "postgres:18.6@sha256:3333333333333333333333333333333333333333333333333333333333333333"
  volumeClaimTemplates:
    - metadata: {name: data}
`

// renderSlot is an unpacked bundle with the files the render reads: its
// release.yaml, product.yaml, helm and the chart archive.
func renderSlot(t *testing.T, productYAML string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"release.yaml":                   renderRelease,
		"product.yaml":                   productYAML,
		"helm":                           "not run",
		"charts/postgres-ha-1.0.2.tgz":   "the archive",
		"manifests/sneakers-data/a.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: other}\n",
	} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil { // #nosec G306 -- test files
			t.Fatal(err)
		}
	}
	return dir
}

type call struct {
	helm   string
	args   []string
	env    []string
	values string
}

// fakeHelm answers a template with renderOut and keeps what it was asked.
func fakeHelm(t *testing.T, got *call) product.HelmRunner {
	t.Helper()
	return func(_ context.Context, helm string, env []string, args ...string) ([]byte, error) {
		*got = call{helm: helm, args: args, env: env}
		for i, a := range args {
			if a == "-f" && i+1 < len(args) {
				b, err := os.ReadFile(args[i+1])
				if err != nil {
					return nil, err
				}
				got.values = string(b)
			}
		}
		return []byte(renderOut), nil
	}
}

// The box renders the bundle's chart with the slot's own helm and puts the
// result in its phase's stack, beside what the bundle already put there.
func TestRenderResourcesWritesTheClusterIntoItsPhaseStack(t *testing.T) {
	dir := renderSlot(t, renderProduct)
	var got call
	if err := product.RenderResources(context.Background(), dir, fakeHelm(t, &got), nil); err != nil {
		t.Fatal(err)
	}
	if got.helm != filepath.Join(dir, "helm") {
		t.Errorf("helm = %q, not the slot's own", got.helm)
	}
	args := strings.Join(got.args, " ")
	for _, w := range []string{"template sneakers-pgha " + filepath.Join(dir, "charts", "postgres-ha-1.0.2.tgz"), "--namespace sneakers", "--skip-tests"} {
		if !strings.Contains(args, w) {
			t.Errorf("helm %s lacks %q", args, w)
		}
	}
	if !strings.Contains(got.values, "fullnameOverride: sneakers-pgha") || !strings.Contains(got.values, "max_connections: 100") {
		t.Errorf("the values file:\n%s", got.values)
	}
	b, err := os.ReadFile(filepath.Join(dir, "manifests", "sneakers-data", "resources-postgres-ha.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "sneakers-appliance/phase") {
		t.Errorf("the workload isn't labelled with its phase:\n%s", b)
	}
	if !strings.Contains(string(b), "/var/lib/sneakers-data") || strings.Contains(string(b), "volumeClaimTemplates") {
		t.Errorf("the volume isn't a hostPath:\n%s", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "manifests", "sneakers-data", "a.yaml")); err != nil {
		t.Errorf("the bundle's own file in the stack: %v", err)
	}
	// helm's cache and settings are somewhere writable, and are gone after.
	var home string
	for _, e := range got.env {
		if v, ok := strings.CutPrefix(e, "HELM_CACHE_HOME="); ok {
			home = v
		}
	}
	if home == "" || strings.HasPrefix(home, dir) {
		t.Errorf("HELM_CACHE_HOME = %q", home)
	}
	if _, err := os.Stat(home); err == nil {
		t.Errorf("helm's scratch %s is left behind", home)
	}
}

func TestRenderResourcesDoesNothingWithoutAResourcesSection(t *testing.T) {
	dir := renderSlot(t, strings.Split(renderProduct, "resources:")[0])
	called := false
	run := func(context.Context, string, []string, ...string) ([]byte, error) { called = true; return nil, nil }
	if err := product.RenderResources(context.Background(), dir, run, nil); err != nil || called {
		t.Fatalf("err %v, helm run %v", err, called)
	}
	if _, err := os.Stat(filepath.Join(dir, "manifests", "sneakers-data", "resources-postgres-ha.yaml")); err == nil {
		t.Error("a stack file was written")
	}
}

func TestRenderResourcesRefusesWhatItCannotRender(t *testing.T) {
	for name, c := range map[string]struct {
		edit func(dir string)
		run  product.HelmRunner
		want string
	}{
		"no helm in the bundle": {func(dir string) { _ = os.Remove(filepath.Join(dir, "helm")) }, nil, "helm"},
		"no chart archive":      {func(dir string) { _ = os.Remove(filepath.Join(dir, "charts", "postgres-ha-1.0.2.tgz")) }, nil, "postgres-ha-1.0.2.tgz"},
		"helm failing": {nil, func(context.Context, string, []string, ...string) ([]byte, error) {
			return nil, errors.New("exit status 1: Error: boom")
		}, "boom"},
		"a render the product's phases don't cover": {nil, func(context.Context, string, []string, ...string) ([]byte, error) {
			return []byte(strings.Replace(renderOut, "name: sneakers-pgha}", "name: sneakers-other}", 1)), nil
		}, "sneakers-other"},
	} {
		dir := renderSlot(t, renderProduct)
		if c.edit != nil {
			c.edit(dir)
		}
		run := c.run
		if run == nil {
			run = func(context.Context, string, []string, ...string) ([]byte, error) {
				t.Errorf("%s: helm ran", name)
				return nil, nil
			}
		}
		err := product.RenderResources(context.Background(), dir, run, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
		if _, serr := os.Stat(filepath.Join(dir, "manifests", "sneakers-data", "resources-postgres-ha.yaml")); serr == nil {
			t.Errorf("%s: a stack file is left", name)
		}
	}
}

// With a real helm (HELM_BIN, the binary's path), the box's exec of it
// renders a chart archive: the release name, the namespace and the
// product's values reach the templates.
func TestRenderResourcesWithARealHelm(t *testing.T) {
	bin := os.Getenv("HELM_BIN")
	if bin == "" {
		t.Skip("HELM_BIN names no helm")
	}
	dir := renderSlot(t, renderProduct)
	if err := os.Remove(filepath.Join(dir, "helm")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(bin, filepath.Join(dir, "helm")); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct{ name, body string }{
		{"postgres-ha/Chart.yaml", "apiVersion: v2\nname: postgres-ha\nversion: 1.0.2\n"},
		{"postgres-ha/values.yaml", "fullnameOverride: x\npostgresql:\n  parameters: {}\n"},
		{"postgres-ha/templates/sts.yaml", `apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: {{ .Values.fullnameOverride }}
  namespace: {{ .Release.Namespace }}
  labels: {app.kubernetes.io/instance: {{ .Release.Name }}}
spec:
  template:
    spec:
      securityContext: {runAsUser: 999}
      containers:
        - name: postgres
          image: "postgres:18.6@sha256:3333333333333333333333333333333333333333333333333333333333333333"
          env: [{name: MAX, value: {{ .Values.postgresql.parameters.max_connections | quote }}}]
`},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := errors.Join(tw.Close(), gz.Close()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "charts", "postgres-ha-1.0.2.tgz"), buf.Bytes(), 0o644); err != nil { // #nosec G306 -- a test file
		t.Fatal(err)
	}
	if err := product.RenderResources(context.Background(), dir, product.ExecHelm, nil); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "manifests", "sneakers-data", "resources-postgres-ha.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"name: sneakers-pgha", "namespace: sneakers", "app.kubernetes.io/instance: sneakers-pgha", `"100"`} {
		if !strings.Contains(string(b), w) {
			t.Errorf("the stack lacks %q:\n%s", w, b)
		}
	}
}
