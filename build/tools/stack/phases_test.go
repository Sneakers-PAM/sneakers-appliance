// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const phasedProductYAML = productYAML + `switches:
  - {name: mcp, label: The MCP server, stacks: [sneakers-mcp]}
phases:
  - {name: data, label: The database, stack: sneakers-data, workloads: [sneakers-postgres]}
  - {name: front, label: The gateway, stack: sneakers-front, workloads: [sneakers-gateway, sneakers-mcp], switch_stacks: [sneakers-mcp]}
`

func renderPhased(t *testing.T, product string) (string, error) {
	t.Helper()
	dir := t.TempDir()
	w := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	o := options{
		Release: w("release.yaml", release), ProductYAML: w("product.yaml", product),
		Off: w("off.yaml", off), On: w("on.yaml", strings.Replace(on, `MCP_ENABLED: "false"`, `MCP_ENABLED: "true"`, 1)),
		Out: filepath.Join(dir, "stacks"), Namespace: "sneakers", Stack: "sneakers", SwitchStack: "sneakers-mcp",
		SwitchConfigMap: "sneakers-mcp-switch", SwitchFrom: []string{"sneakers-gateway"}, Data: "/var/lib/sneakers-data",
	}
	return o.Out, render(o, &bytes.Buffer{})
}

func readStack(t *testing.T, out, stack string) map[string]map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(out, stack, stack+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return docs(t, string(b))
}

func labels(d map[string]any, path ...string) map[string]any {
	for _, k := range path {
		next, _ := d[k].(map[string]any)
		if next == nil {
			return nil
		}
		d = next
	}
	l, _ := d["labels"].(map[string]any)
	return l
}

// With phases, each phase's workloads go in the phase's own stack, labelled
// with the phase and its place in the order on the workload and its pods;
// everything else (the Namespace, Services, ConfigMaps, Ingresses) stays in
// the always-on stack, and the switch's workloads stay in the switch's
// stack with their phase's labels.
func TestRenderSplitsTheWorkloadsByPhase(t *testing.T) {
	out, err := renderPhased(t, phasedProductYAML)
	if err != nil {
		t.Fatal(err)
	}
	main := readStack(t, out, "sneakers")
	for _, k := range []string{"Deployment/sneakers-gateway", "StatefulSet/sneakers-postgres"} {
		if _, ok := main[k]; ok {
			t.Errorf("%s is in the always-on stack", k)
		}
	}
	for _, k := range []string{"Namespace/sneakers", "ConfigMap/sneakers-gateway", "Ingress/sneakers-gateway"} {
		if _, ok := main[k]; !ok {
			t.Errorf("%s isn't in the always-on stack", k)
		}
	}
	for stack, want := range map[string]struct{ key, phase, order string }{
		"sneakers-data":  {"StatefulSet/sneakers-postgres", "data", "1"},
		"sneakers-front": {"Deployment/sneakers-gateway", "front", "2"},
		"sneakers-mcp":   {"Deployment/sneakers-mcp", "front", "2"},
	} {
		s := readStack(t, out, stack)
		d, ok := s[want.key]
		if !ok {
			t.Errorf("%s isn't in %s: %v", want.key, stack, s)
			continue
		}
		if d["metadata"].(map[string]any)["namespace"] != "sneakers" {
			t.Errorf("%s has no namespace", want.key)
		}
		for _, l := range []map[string]any{labels(d, "metadata"), labels(d, "spec", "template", "metadata")} {
			if l["sneakers-appliance/phase"] != want.phase || l["sneakers-appliance/phase-order"] != want.order {
				t.Errorf("%s in %s: labels %v", want.key, stack, l)
			}
		}
	}
	if _, ok := readStack(t, out, "sneakers-mcp")["ConfigMap/sneakers-mcp-switch"]; !ok {
		t.Error("the switch's ConfigMap left the switch's stack")
	}
}

// A workload no phase names, or a switch workload whose phase doesn't
// place the switch's stack, is refused: nothing slips in unordered.
func TestRenderRefusesAnUnphasedWorkload(t *testing.T) {
	for name, tc := range map[string]struct{ product, want string }{
		"a workload in no phase": {strings.Replace(phasedProductYAML, "workloads: [sneakers-postgres]", "workloads: [sneakers-valkey]", 1), "sneakers-postgres"},
		"a switch workload whose phase doesn't place the switch stack": {
			strings.Replace(strings.Replace(phasedProductYAML, ", switch_stacks: [sneakers-mcp]", "", 1), "workloads: [sneakers-gateway, sneakers-mcp]", "workloads: [sneakers-gateway]", 1) +
				"  - {name: late, label: Late, stack: sneakers-late, workloads: [sneakers-mcp]}\n",
			"sneakers-mcp",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := renderPhased(t, tc.product); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want a refusal naming %s", err, tc.want)
			}
		})
	}
}

// Without phases the render is what it was: every workload in the
// always-on stack, unlabelled.
func TestRenderWithoutPhasesKeepsOneStack(t *testing.T) {
	main, _, err := run(t, off, on, productYAML)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(main, "sneakers-appliance/phase") {
		t.Fatal("an unphased render carries phase labels")
	}
}

const phasedRelease = release + `  jobs:
    migrate:
      image: ghcr.io/sneakers-pam/sneakers-migrate
      digest: sha256:4444444444444444444444444444444444444444444444444444444444444444
`

// Every phased workload starts with the wait init container: the wait
// image (the release's migrate Job image) resolves the cluster's DNS,
// then connects to each Service its phase says it needs, so a pod the
// kubelet starts out of order (after a power loss) waits instead of
// crashing.
func TestRenderGivesEachPhasedWorkloadItsWait(t *testing.T) {
	product := strings.Replace(phasedProductYAML, "switch_stacks: [sneakers-mcp]}", "switch_stacks: [sneakers-mcp], needs: {sneakers-gateway: [sneakers-postgres:5432]}}", 1)
	dir := t.TempDir()
	w := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	o := options{
		Release: w("release.yaml", phasedRelease), ProductYAML: w("product.yaml", product),
		Off: w("off.yaml", off), On: w("on.yaml", strings.Replace(on, `MCP_ENABLED: "false"`, `MCP_ENABLED: "true"`, 1)),
		Out: filepath.Join(dir, "stacks"), Namespace: "sneakers", Stack: "sneakers", SwitchStack: "sneakers-mcp",
		SwitchConfigMap: "sneakers-mcp-switch", SwitchFrom: []string{"sneakers-gateway"}, Data: "/var/lib/sneakers-data", WaitJob: "migrate",
	}
	if err := render(o, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	wantImage := "ghcr.io/sneakers-pam/sneakers-migrate@sha256:4444444444444444444444444444444444444444444444444444444444444444"
	for stack, want := range map[string]struct{ key, args string }{
		"sneakers-front": {"Deployment/sneakers-gateway", "wait --dns kubernetes.default.svc.cluster.local --tcp sneakers-postgres.sneakers.svc:5432 --every 2s"},
		"sneakers-data":  {"StatefulSet/sneakers-postgres", "wait --dns kubernetes.default.svc.cluster.local --every 2s"},
		"sneakers-mcp":   {"Deployment/sneakers-mcp", "wait --dns kubernetes.default.svc.cluster.local --every 2s"},
	} {
		d := readStack(t, out(o), stack)[want.key]
		inits := d["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["initContainers"].([]any)
		first := inits[0].(map[string]any)
		if first["name"] != "wait-phase" || first["image"] != wantImage || first["imagePullPolicy"] != "Never" {
			t.Fatalf("%s's first init container %v", want.key, first)
		}
		if got := strings.Join(toStrings(first["args"]), " "); got != want.args {
			t.Errorf("%s waits with %q, want %q", want.key, got, want.args)
		}
		sc := first["securityContext"].(map[string]any)
		if sc["runAsNonRoot"] != true || sc["readOnlyRootFilesystem"] != true || sc["allowPrivilegeEscalation"] != false {
			t.Errorf("%s's wait runs with %v", want.key, sc)
		}
	}
	main := readStack(t, out(o), "sneakers")
	if strings.Contains(fmt.Sprint(main), "wait-phase") {
		t.Fatal("the always-on stack has a wait")
	}
}

// A phased render needs the wait image: a release without the Job image
// it names is refused.
func TestRenderRefusesAPhasedProductWithoutItsWaitImage(t *testing.T) {
	dir := t.TempDir()
	w := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	o := options{
		Release: w("release.yaml", release), ProductYAML: w("product.yaml", phasedProductYAML),
		Off: w("off.yaml", off), On: w("on.yaml", on),
		Out: filepath.Join(dir, "stacks"), Namespace: "sneakers", Stack: "sneakers", SwitchStack: "sneakers-mcp",
		SwitchConfigMap: "sneakers-mcp-switch", SwitchFrom: []string{"sneakers-gateway"}, Data: "/var/lib/sneakers-data", WaitJob: "migrate",
	}
	if err := render(o, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "migrate") {
		t.Fatalf("got %v, want a refusal naming the wait Job image", err)
	}
}

func out(o options) string { return o.Out }
