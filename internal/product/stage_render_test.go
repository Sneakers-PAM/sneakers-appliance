// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package product_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func digestOfBytes(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// withResourcesChart makes the fixture bundle one whose product.yaml has a
// resources section naming its pinned valkey chart, carried in charts/.
func withResourcesChart(t *testing.T) func(fstest.MapFS) {
	t.Helper()
	return func(m fstest.MapFS) {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		body := "apiVersion: v2\nname: valkey\nversion: 1.0.2\n"
		if err := tw.WriteHeader(&tar.Header{Name: "valkey/Chart.yaml", Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
		if err := errors.Join(tw.Close(), gz.Close()); err != nil {
			t.Fatal(err)
		}
		tgz := buf.Bytes()
		man, err := json.Marshal(map[string]any{
			"schemaVersion": 2,
			"config":        map[string]any{"mediaType": "application/vnd.cncf.helm.config.v1+json", "digest": digestOfBytes([]byte("{}")), "size": 2},
			"layers":        []map[string]any{{"mediaType": "application/vnd.cncf.helm.chart.content.v1.tar+gzip", "digest": digestOfBytes(tgz), "size": len(tgz)}},
		})
		if err != nil {
			t.Fatal(err)
		}
		var rel map[string]any
		if err := json.Unmarshal(m["release.yaml"].Data, &rel); err != nil {
			t.Fatal(err)
		}
		entry := rel["spec"].(map[string]any)["thirdParty"].(map[string]any)["valkey"].(map[string]any)
		entry["chart"] = map[string]any{"name": "valkey", "version": "1.0.2", "repository": "oci://example.org/charts", "digest": digestOfBytes(man)}
		b, err := json.Marshal(rel)
		if err != nil {
			t.Fatal(err)
		}
		m["release.yaml"] = &fstest.MapFile{Data: b}
		m["product.yaml"] = &fstest.MapFile{Data: []byte("format: 2\nphases:\n  - {name: data, label: The database, stack: hello, workloads: [db]}\nresources:\n  chart: valkey\n  phase: data\n  release: db\n  namespace: hello\n  data: /var/lib/x\n  values: {a: 1}\n")}
		m["charts/valkey-1.0.2.tgz"] = &fstest.MapFile{Data: tgz}
		m["charts/valkey-1.0.2.manifest.json"] = &fstest.MapFile{Data: man}
	}
}

// Staging a product whose product.yaml has a resources section renders it
// with the new slot's own helm, and a render that fails refuses the bundle
// and leaves no slot behind.
func TestStagingRendersTheResourcesChartWithTheSlotsHelm(t *testing.T) {
	e := newEnv(t, withResourcesChart(t))
	var helm string
	e.slots.Helm = func(_ context.Context, h string, _ []string, _ ...string) ([]byte, error) {
		helm = h
		return nil, errors.New("helm refused")
	}
	err := e.slots.Stage(header("0.2.0"), e.fill, e.key)
	if err == nil || !strings.Contains(err.Error(), "helm refused") {
		t.Fatalf("stage: %v", err)
	}
	if filepath.Base(helm) != "helm" || !strings.HasPrefix(helm, e.slots.Dir) {
		t.Errorf("helm ran as %q, not the slot's", helm)
	}
	if st := e.slots.Status(); st.Staged != "" {
		t.Errorf("a slot is staged: %+v", st)
	}
	for _, s := range []string{"a", "b"} {
		if _, err := os.Stat(filepath.Join(e.slots.Dir, s)); err == nil {
			t.Errorf("slot %s is left behind", s)
		}
	}
}

// A product with no resources section never runs helm.
func TestStagingAProductWithoutResourcesRunsNoHelm(t *testing.T) {
	e := newEnv(t, nil)
	e.slots.Helm = func(context.Context, string, []string, ...string) ([]byte, error) {
		t.Error("helm ran")
		return nil, nil
	}
	e.stage(t, "0.2.0")
}
