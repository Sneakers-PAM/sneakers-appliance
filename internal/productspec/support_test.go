// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productspec

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSupportSectionsParse(t *testing.T) {
	s, err := Parse([]byte(`format: 2
support:
  - title: The workloads
    kubectl: {verb: get, resource: deployments, namespace: sneakers}
    short: true
  - title: Every node
    kubectl: {verb: get, resource: nodes}
  - title: The gateway's logs
    kubectl: {verb: logs, namespace: sneakers, selector: "app.kubernetes.io/name=sneakers-gateway", tail: 300}
    timeout: 30s
    redact: ['acct-[0-9]+']
  - title: The database's size
    command: du -s -h /var/lib/sneakers-data/postgres
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Support) != 4 || !s.Support[0].Short || s.Support[2].Deadline() != 30*time.Second || s.Support[3].Deadline() != DefaultSupportTimeout {
		t.Fatalf("parsed %+v", s.Support)
	}
	if got := strings.Join(s.Support[0].Kubectl.Args(50), " "); got != "get deployments -n sneakers -o wide" {
		t.Fatalf("get: %s", got)
	}
	if got := strings.Join(s.Support[1].Kubectl.Args(50), " "); got != "get nodes -A -o wide" {
		t.Fatalf("get: %s", got)
	}
	if got := strings.Join(s.Support[2].Kubectl.Args(50), " "); got != "logs -n sneakers -l app.kubernetes.io/name=sneakers-gateway --all-containers --prefix --timestamps --tail=300" {
		t.Fatalf("logs: %s", got)
	}
	if !slices.Equal(s.Support[3].Words(), []string{"du", "-s", "-h", "/var/lib/sneakers-data/postgres"}) {
		t.Fatalf("words %v", s.Support[3].Words())
	}
}

// What a product may not ask of the box: anything that writes, anything
// unbounded, anything outside its data, anything that reads a secret, and
// anything the box's busybox wasn't built with.
func TestSupportSectionsAreRefused(t *testing.T) {
	cases := map[string]string{
		"no title":          `{command: uptime}`,
		"two lines":         "{title: \"a\\nb\", command: uptime}",
		"neither":           `{title: x}`,
		"both":              `{title: x, command: uptime, kubectl: {verb: get, resource: pods}}`,
		"long timeout":      `{title: x, command: uptime, timeout: 5m}`,
		"bad timeout":       `{title: x, command: uptime, timeout: soon}`,
		"bad pattern":       `{title: x, command: uptime, redact: ["("]}`,
		"empty pattern":     `{title: x, command: uptime, redact: [""]}`,
		"writes":            `{title: x, command: rm -rf /var/lib/sneakers-data}`,
		"sed":               `{title: x, command: sed -i s/a/b/ /var/lib/sneakers-data/x}`,
		"find":              `{title: x, command: find /var/lib/sneakers-data -delete}`,
		"a shell":           `{title: x, command: sh -c uptime}`,
		"pipe":              `{title: x, command: "cat /var/lib/sneakers-data/x | sh"}`,
		"redirect":          `{title: x, command: "cat /var/lib/sneakers-data/x > /tmp/y"}`,
		"substitution":      `{title: x, command: "cat $(id)"}`,
		"the state volume":  `{title: x, command: cat /var/lib/sneakers/platform/box-secrets}`,
		"the kubeconfig":    `{title: x, command: cat /var/lib/k0s/pki/admin.conf}`,
		"escape":            `{title: x, command: cat /var/lib/sneakers-data/../sneakers/x}`,
		"a sibling":         `{title: x, command: cat /var/lib/sneakers-data-other/x}`,
		"relative":          `{title: x, command: cat postgres/x}`,
		"unknown flag":      `{title: x, command: ls -R /var/lib/sneakers-data}`,
		"clustered flags":   `{title: x, command: ls -la /var/lib/sneakers-data}`,
		"unbuilt option":    `{title: x, command: tail -f /var/lib/sneakers-data/x}`,
		"tail no number":    `{title: x, command: tail -n /var/lib/sneakers-data/x}`,
		"operand on free":   `{title: x, command: free /var/lib/sneakers-data}`,
		"secrets":           `{title: x, kubectl: {verb: get, resource: secrets}}`,
		"describe secret":   `{title: x, kubectl: {verb: describe, resource: secret, namespace: sneakers}}`,
		"configmaps":        `{title: x, kubectl: {verb: describe, resource: configmaps, namespace: sneakers}}`,
		"delete":            `{title: x, kubectl: {verb: delete, resource: pods, namespace: sneakers}}`,
		"exec":              `{title: x, kubectl: {verb: exec, namespace: sneakers, selector: a=b}}`,
		"logs no selector":  `{title: x, kubectl: {verb: logs, namespace: sneakers}}`,
		"logs no namespace": `{title: x, kubectl: {verb: logs, selector: a=b}}`,
		"logs a resource":   `{title: x, kubectl: {verb: logs, resource: pods, namespace: sneakers, selector: a=b}}`,
		"describe all":      `{title: x, kubectl: {verb: describe, resource: pods}}`,
		"bad namespace":     `{title: x, kubectl: {verb: get, resource: pods, namespace: "a b"}}`,
		"flag in namespace": `{title: x, kubectl: {verb: get, resource: pods, namespace: "--all"}}`,
		"flag in selector":  `{title: x, kubectl: {verb: logs, namespace: a, selector: "a=b --kubeconfig=x"}}`,
		"huge tail":         `{title: x, kubectl: {verb: logs, namespace: a, selector: a=b, tail: 100000}}`,
		"tail on get":       `{title: x, kubectl: {verb: get, resource: pods, tail: 5}}`,
		"previous on get":   `{title: x, kubectl: {verb: get, resource: pods, previous: true}}`,
	}
	for name, section := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte("format: 2\nsupport:\n  - " + section + "\n")); err == nil {
				t.Fatalf("%s was accepted", section)
			}
		})
	}
	t.Run("twice", func(t *testing.T) {
		if _, err := Parse([]byte("format: 2\nsupport:\n  - {title: x, command: uptime}\n  - {title: x, command: uptime}\n")); err == nil {
			t.Fatal("a title twice was accepted")
		}
	})
	t.Run("too many", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("format: 2\nsupport:\n")
		for i := range MaxSupportSections + 1 {
			b.WriteString("  - {title: \"s" + strings.Repeat("x", i) + "\", command: uptime}\n")
		}
		if _, err := Parse([]byte(b.String())); err == nil {
			t.Fatal("too many sections were accepted")
		}
	})
}

// The options busybox builds only with a further option, for the applets a
// section may run; os/k0s/busybox_test.go keeps the same list for scripts.
var supportGated = map[string]string{
	"df -h": "CONFIG_FEATURE_HUMAN_READABLE", "du -h": "CONFIG_FEATURE_HUMAN_READABLE", "ls -h": "CONFIG_FEATURE_HUMAN_READABLE",
	"ls --full-time": "CONFIG_FEATURE_LS_TIMESTAMPS",
}

// Every applet and option a section may use is built into the box's
// busybox: 6 of 35 commands once failed on a box for want of an applet.
func TestSupportAppletsAreInTheBoxBusybox(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "build", "busybox", "busybox.config"))
	if err != nil {
		t.Fatal(err)
	}
	on := map[string]bool{}
	for line := range strings.Lines(string(b)) {
		if sym, ok := strings.CutSuffix(strings.TrimSpace(line), "=y"); ok {
			on[sym] = true
		}
	}
	for applet, opts := range SupportApplets() {
		if !on["CONFIG_"+strings.ToUpper(applet)] {
			t.Errorf("%s isn't built", applet)
		}
		for _, o := range opts {
			if sym, gated := supportGated[applet+" "+o]; gated && !on[sym] {
				t.Errorf("%s %s needs %s", applet, o, sym)
			}
		}
	}
}

// The Sneakers bundle declares its own sections; the base names none of
// them.
func TestTheSneakersBundleDeclaresItsSections(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "build", "product", "sneakers", "product.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	short := 0
	for _, c := range s.Support {
		if c.Short {
			short++
		}
	}
	if len(s.Support) == 0 || short == 0 {
		t.Fatalf("support %+v", s.Support)
	}
}
