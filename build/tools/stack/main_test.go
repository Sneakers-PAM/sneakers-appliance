// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const release = `apiVersion: sneakers-pam/v1alpha1
kind: Release
spec:
  services:
    gateway:
      image: ghcr.io/sneakers-pam/sneakers-gateway
      digest: sha256:1111111111111111111111111111111111111111111111111111111111111111
    mcp:
      image: ghcr.io/sneakers-pam/sneakers-mcp
      digest: sha256:2222222222222222222222222222222222222222222222222222222222222222
  thirdParty:
    postgres:
      image: docker.io/library/postgres
      digest: sha256:3333333333333333333333333333333333333333333333333333333333333333
`

const productYAML = `format: 2
box_secrets:
  - secret: sneakers/sneakers-bundled
    keys: [{key: password, generate: password}]
  - secret: sneakers/sneakers-box
    keys: [{key: KEK, generate: key32}]
`

// off is what helm renders with the switch off: a Deployment reading a
// box secret, the chart's own generated Secret, a PostgreSQL StatefulSet
// with a volume claim, an Ingress with a host and TLS, and the gateway's
// ConfigMap.
const off = `apiVersion: v1
kind: Secret
metadata: {name: sneakers-bundled}
data: {password: c2VjcmV0}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: sneakers-gateway}
data: {MCP_ENABLED: "false", LOG_LEVEL: error}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: data}
spec: {}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: sneakers-gateway}
spec:
  template:
    spec:
      containers:
        - name: gateway
          image: "ghcr.io/sneakers-pam/sneakers-gateway:0.1.0"
          env:
            - name: PGPASSWORD
              valueFrom: {secretKeyRef: {name: sneakers-bundled, key: password}}
            - name: KEK
              valueFrom: {secretKeyRef: {name: sneakers-box, key: KEK}}
---
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: sneakers-postgres}
spec:
  template:
    spec:
      securityContext: {runAsUser: 999}
      containers:
        - name: postgres
          image: "postgres:18.6@sha256:3333333333333333333333333333333333333333333333333333333333333333"
  volumeClaimTemplates:
    - metadata: {name: data}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: sneakers-gateway}
spec:
  tls: [{hosts: [sneakers.example.org], secretName: tls}]
  rules:
    - host: sneakers.example.org
      http: {paths: []}
`

// on adds the MCP server and changes the gateway's MCP settings.
const on = off + `---
apiVersion: apps/v1
kind: Deployment
metadata: {name: sneakers-mcp}
spec:
  template:
    spec:
      containers:
        - name: mcp
          image: ghcr.io/sneakers-pam/sneakers-mcp:0.1.0
`

func run(t *testing.T, offDoc, onDoc, product string) (string, string, error) {
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
		Off: w("off.yaml", offDoc), On: w("on.yaml", strings.Replace(onDoc, `MCP_ENABLED: "false"`, `MCP_ENABLED: "true"`, 1)),
		Out: filepath.Join(dir, "stacks"), Namespace: "sneakers", Stack: "sneakers", SwitchStack: "sneakers-mcp",
		SwitchConfigMap: "sneakers-mcp-switch", SwitchFrom: []string{"sneakers-gateway"}, Data: "/var/lib/sneakers-data",
	}
	var log bytes.Buffer
	if err := render(o, &log); err != nil {
		return "", "", err
	}
	main, err := os.ReadFile(filepath.Join(o.Out, "sneakers", "sneakers.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	sw, err := os.ReadFile(filepath.Join(o.Out, "sneakers-mcp", "sneakers-mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(main), string(sw), nil
}

func docs(t *testing.T, s string) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	dec := yaml.NewDecoder(strings.NewReader(s))
	for {
		var d map[string]any
		if err := dec.Decode(&d); err != nil {
			break
		}
		md := d["metadata"].(map[string]any)
		out[d["kind"].(string)+"/"+md["name"].(string)] = d
	}
	return out
}

func TestRenderMakesTheBoxStacks(t *testing.T) {
	main, sw, err := run(t, off, on, productYAML)
	if err != nil {
		t.Fatal(err)
	}
	m := docs(t, main)
	if _, ok := m["Secret/sneakers-bundled"]; ok || strings.Contains(main, "c2VjcmV0") {
		t.Fatal("the chart's generated Secret is in the stack; the box makes it")
	}
	if _, ok := m["PersistentVolumeClaim/data"]; ok {
		t.Fatal("a PersistentVolumeClaim: the box has no provisioner")
	}
	if _, ok := m["Namespace/sneakers"]; !ok {
		t.Fatal("no Namespace")
	}
	gw := m["Deployment/sneakers-gateway"]
	if gw["metadata"].(map[string]any)["namespace"] != "sneakers" {
		t.Fatal("no namespace on the Deployment")
	}
	c := gw["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
	if c["image"] != "ghcr.io/sneakers-pam/sneakers-gateway@sha256:1111111111111111111111111111111111111111111111111111111111111111" || c["imagePullPolicy"] != "Never" {
		t.Fatalf("the gateway image %v %v", c["image"], c["imagePullPolicy"])
	}
	pg := m["StatefulSet/sneakers-postgres"]["spec"].(map[string]any)
	if _, ok := pg["volumeClaimTemplates"]; ok {
		t.Fatal("volumeClaimTemplates are kept")
	}
	ps := pg["template"].(map[string]any)["spec"].(map[string]any)
	v := ps["volumes"].([]any)[0].(map[string]any)
	if v["name"] != "data" || v["hostPath"].(map[string]any)["path"] != "/var/lib/sneakers-data/postgres" {
		t.Fatalf("the volume %v", v)
	}
	ic := ps["initContainers"].([]any)[0].(map[string]any)
	if !strings.Contains(strings.Join(toStrings(ic["command"]), " "), "chown 999:999 /data") || ic["image"] != "docker.io/library/postgres@sha256:3333333333333333333333333333333333333333333333333333333333333333" {
		t.Fatalf("the owner init %v", ic)
	}
	ing := m["Ingress/sneakers-gateway"]["spec"].(map[string]any)
	if _, ok := ing["tls"]; ok || strings.Contains(main, "sneakers.example.org") {
		t.Fatal("the Ingress keeps its host or TLS; the box serves every name on 443")
	}
	if _, ok := m["Deployment/sneakers-mcp"]; ok {
		t.Fatal("the MCP is in the always-on stack")
	}
	s := docs(t, sw)
	if _, ok := s["Deployment/sneakers-mcp"]; !ok {
		t.Fatal("the MCP isn't in the switch stack")
	}
	cm := s["ConfigMap/sneakers-mcp-switch"]["data"].(map[string]any)
	if len(cm) != 1 || cm["MCP_ENABLED"] != "true" {
		t.Fatalf("the switch ConfigMap %v", cm)
	}
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func TestRenderRefuses(t *testing.T) {
	for name, tc := range map[string]struct{ off, product, want string }{
		"a Secret no box makes":           {off + "---\napiVersion: v1\nkind: Secret\nmetadata: {name: sneakers-lab}\ndata: {a: Yg==}\n", productYAML, "Secret sneakers-lab"},
		"an unpinned image":               {strings.Replace(off, "postgres:18.6@", "redis:7@", 1), productYAML, "redis"},
		"a Secret read that no box makes": {strings.Replace(off, "name: sneakers-box, key: KEK", "name: sneakers-lab-secrets, key: KEK", 1), productYAML, "sneakers-lab-secrets"},
		"a box secret key not declared":   {strings.Replace(off, "name: sneakers-box, key: KEK", "name: sneakers-box, key: TOTP", 1), productYAML, "sneakers-box"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := run(t, tc.off, tc.off+strings.TrimPrefix(on, off), tc.product)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want a refusal naming %s", err, tc.want)
			}
		})
	}
	// Two switch ConfigMaps that disagree on one setting.
	twice := off + "---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: sneakers-web-staff}\ndata: {MCP_ENABLED: \"false\"}\n"
	onTwice := strings.Replace(twice+strings.TrimPrefix(on, off), `MCP_ENABLED: "false"}`, `MCP_ENABLED: "maybe"}`, 1)
	dir := t.TempDir()
	w := func(name, body string) string {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	o := options{Release: w("r", release), ProductYAML: w("p", productYAML), Off: w("off", twice),
		On:  w("on", strings.Replace(onTwice, `MCP_ENABLED: "false", LOG_LEVEL`, `MCP_ENABLED: "true", LOG_LEVEL`, 1)),
		Out: filepath.Join(dir, "out"), Namespace: "sneakers", Stack: "sneakers", SwitchStack: "sneakers-mcp", SwitchConfigMap: "sneakers-mcp-switch",
		SwitchFrom: []string{"sneakers-gateway", "sneakers-web-staff"}, Data: "/var/lib/sneakers-data"}
	if err := render(o, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "MCP_ENABLED") {
		t.Fatalf("two switch settings that disagree: %v", err)
	}
}
