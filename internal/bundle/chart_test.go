// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bundle_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sigbundle"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
)

const (
	chartMedia  = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
	chartTGZ    = "charts/valkey-1.0.2.tgz"
	chartManif  = "charts/valkey-1.0.2.manifest.json"
	chartSpec   = "format: 2\nresources:\n  chart: valkey\n"
	chartRepo   = "oci://example.org/charts"
	chartPinned = "valkey"
)

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// chartTGZBytes is a helm chart archive: one folder holding Chart.yaml.
func chartTGZBytes(t *testing.T, name, version string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := fmt.Sprintf("apiVersion: v2\nname: %s\nversion: %s\n", name, version)
	for _, f := range []struct{ name, body string }{{name + "/Chart.yaml", body}, {name + "/values.yaml", "replicas: 3\n"}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// chartManifest is the OCI manifest the registry serves for tgz.
func chartManifest(t *testing.T, tgz []byte) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"config":        map[string]any{"mediaType": "application/vnd.cncf.helm.config.v1+json", "digest": sum([]byte("{}")), "size": 2},
		"layers":        []map[string]any{{"mediaType": chartMedia, "digest": sum(tgz), "size": len(tgz)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// pinChart gives the release's thirdParty entry the chart pin, digest being
// the registry manifest's.
func pinChart(t *testing.T, m fstest.MapFS, version, digest string) {
	t.Helper()
	var rel map[string]any
	if err := json.Unmarshal(m[bundle.ProductRelease].Data, &rel); err != nil {
		t.Fatal(err)
	}
	entry := rel["spec"].(map[string]any)["thirdParty"].(map[string]any)[chartPinned].(map[string]any)
	entry["chart"] = map[string]any{"name": chartPinned, "version": version, "repository": chartRepo, "digest": digest}
	b, err := json.Marshal(rel)
	if err != nil {
		t.Fatal(err)
	}
	m[bundle.ProductRelease] = &fstest.MapFile{Data: b}
}

// withChart is a product bundle whose product.yaml names the pinned chart
// and which carries it, built to pass; edit then breaks one thing.
func withChart(t *testing.T, edit func(fstest.MapFS)) func(fstest.MapFS) {
	return func(m fstest.MapFS) {
		tgz := chartTGZBytes(t, chartPinned, "1.0.2")
		man := chartManifest(t, tgz)
		pinChart(t, m, "1.0.2", sum(man))
		m["product.yaml"] = &fstest.MapFile{Data: []byte(chartSpec), Mode: 0o644}
		m[chartTGZ] = &fstest.MapFile{Data: tgz, Mode: 0o644}
		m[chartManif] = &fstest.MapFile{Data: man, Mode: 0o644}
		if edit != nil {
			edit(m)
		}
	}
}

func TestABundleCarriesTheChartItsProductNames(t *testing.T) {
	k := fixtures.LabKeys(t)
	pub, _ := sigbundle.ParsePublicKey(k.Cosign.PublicPEM)
	tree, _ := fixtures.ProductTree(t, k, "amd64", withChart(t, nil))
	if _, err := bundle.CheckProduct(tree, "amd64", pub); err != nil {
		t.Fatal(err)
	}
}

func TestABundleRefusesAChartThatIsNotTheOneReleaseYamlPins(t *testing.T) {
	k := fixtures.LabKeys(t)
	pub, _ := sigbundle.ParsePublicKey(k.Cosign.PublicPEM)
	other := chartTGZBytes(t, chartPinned, "1.0.2")
	other = append(other[:len(other):len(other)], 0) // trailing byte: another archive, same chart
	cases := map[string]struct {
		edit func(fstest.MapFS)
		want string
	}{
		"no archive":  {func(m fstest.MapFS) { delete(m, chartTGZ) }, chartTGZ},
		"no manifest": {func(m fstest.MapFS) { delete(m, chartManif) }, chartManif},
		"another archive": {func(m fstest.MapFS) {
			m[chartTGZ] = &fstest.MapFile{Data: other}
		}, "layer"},
		"another manifest": {func(m fstest.MapFS) {
			m[chartManif] = &fstest.MapFile{Data: append(m[chartManif].Data, ' ')}
		}, "digest"},
		"another chart's archive": {func(m fstest.MapFS) {
			tgz := chartTGZBytes(t, "other", "1.0.2")
			m[chartTGZ] = &fstest.MapFile{Data: tgz}
			m[chartManif] = &fstest.MapFile{Data: chartManifest(t, tgz)}
			pinChart(t, m, "1.0.2", sum(m[chartManif].Data))
		}, "Chart.yaml"},
		"another version's archive": {func(m fstest.MapFS) {
			tgz := chartTGZBytes(t, chartPinned, "1.0.1")
			m[chartTGZ] = &fstest.MapFile{Data: tgz}
			m[chartManif] = &fstest.MapFile{Data: chartManifest(t, tgz)}
			pinChart(t, m, "1.0.2", sum(m[chartManif].Data))
		}, "Chart.yaml"},
		"a chart release.yaml doesn't pin": {func(m fstest.MapFS) {
			m["product.yaml"] = &fstest.MapFile{Data: []byte("format: 2\nresources:\n  chart: nosuch\n")}
		}, "nosuch"},
		"a stray file": {func(m fstest.MapFS) { m["charts/notes.txt"] = &fstest.MapFile{Data: []byte("x")} }, "notes.txt"},
		"charts with no resources": {func(m fstest.MapFS) {
			m["product.yaml"] = &fstest.MapFile{Data: []byte("format: 2\n")}
		}, "charts"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			tree, _ := fixtures.ProductTree(t, k, "amd64", withChart(t, c.edit))
			_, err := bundle.CheckProduct(tree, "amd64", pub)
			if !codes.Is(err, codes.KitBundleMismatch) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want KIT_BUNDLE_MISMATCH naming %q, got %v", c.want, err)
			}
		})
	}
}
