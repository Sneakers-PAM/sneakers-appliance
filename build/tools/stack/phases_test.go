// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
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
