// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package stackconv

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// chartProduct names the data phase's workloads the way the real product
// does: the old cluster, which the umbrella render holds, and the cluster
// the box renders from its own chart.
const chartProduct = productYAML + `phases:
  - {name: data, label: The database, stack: sneakers-data, workloads: [sneakers-postgres, sneakers-pgha]}
  - {name: front, label: The gateway, stack: sneakers-front, workloads: [sneakers-gateway]}
`

// chartRender is what helm renders for the cluster's chart alone.
const chartRender = `apiVersion: v1
kind: Service
metadata: {name: sneakers-pgha-primary}
spec: {ports: [{port: 5432}]}
---
apiVersion: v1
kind: Secret
metadata: {name: sneakers-bundled}
data: {password: c2VjcmV0}
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

func renderChart(t *testing.T, product, rendered string) (string, error) {
	t.Helper()
	dir := t.TempDir()
	w := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	o := ChartOptions{
		Release: w("release.yaml", release), ProductYAML: w("product.yaml", product), Rendered: w("chart.yaml", rendered),
		Namespace: "sneakers", Phase: "data", Data: "/var/lib/sneakers-data",
		Out: filepath.Join(dir, "sneakers-data", "sneakers-pgha.yaml"),
	}
	err := RenderChart(o, &bytes.Buffer{})
	return o.Out, err
}

// A chart the box renders at apply time goes whole into its phase's stack:
// its workloads labelled with the phase, its volume a hostPath, its
// Service beside them, no Namespace (the always-on stack makes it).
func TestRenderChartPutsTheWholeChartInItsPhaseStack(t *testing.T) {
	out, err := renderChart(t, chartProduct, strings.Replace(chartRender, "apiVersion: v1\nkind: Secret\nmetadata: {name: sneakers-bundled}\ndata: {password: c2VjcmV0}\n---\n", "", 1))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := docs(t, string(b))
	for _, k := range []string{"StatefulSet/sneakers-pgha", "Service/sneakers-pgha-primary"} {
		if _, ok := got[k]; !ok {
			t.Errorf("%s isn't in the phase stack: %v", k, keys(got))
		}
	}
	if _, ok := got["Namespace/sneakers"]; ok {
		t.Error("the phase stack makes the Namespace")
	}
	ss := got["StatefulSet/sneakers-pgha"]
	if l := labels(ss, "metadata"); l["sneakers-appliance/phase"] != "data" || l["sneakers-appliance/phase-order"] != "1" {
		t.Errorf("the workload's labels: %v", l)
	}
	if l := labels(ss, "spec", "template", "metadata"); l["sneakers-appliance/phase"] != "data" {
		t.Errorf("the pod's labels: %v", l)
	}
	if md, _ := ss["metadata"].(map[string]any); md["namespace"] != "sneakers" {
		t.Errorf("the namespace: %v", md["namespace"])
	}
	if strings.Contains(string(b), "volumeClaimTemplates") || !strings.Contains(string(b), "/var/lib/sneakers-data") {
		t.Errorf("the volume isn't a hostPath:\n%s", b)
	}
}

func TestRenderChartRefusesWhatABundleNeverCarries(t *testing.T) {
	for name, c := range map[string]struct{ product, rendered, want string }{
		"a Secret no box secret declares":     {chartProduct, strings.Replace(chartRender, "sneakers-bundled", "chart-made", 1), "chart-made"},
		"a workload no phase names":           {chartProduct, strings.Replace(chartRender, "name: sneakers-pgha}\nspec:\n  template", "name: sneakers-other}\nspec:\n  template", 1), "sneakers-other"},
		"a workload of another phase":         {strings.NewReplacer("workloads: [sneakers-postgres, sneakers-pgha]", "workloads: [sneakers-postgres]", "workloads: [sneakers-gateway]", "workloads: [sneakers-gateway, sneakers-pgha]").Replace(chartProduct), chartRender, "belongs to the phase front"},
		"a chart workload the phases dropped": {strings.Replace(chartProduct, "workloads: [sneakers-postgres, sneakers-pgha]", "workloads: [sneakers-postgres]", 1), chartRender, "sneakers-pgha"},
	} {
		if _, err := renderChart(t, c.product, c.rendered); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func keys(m map[string]map[string]any) []string {
	var k []string
	for n := range m {
		k = append(k, n)
	}
	return k
}
