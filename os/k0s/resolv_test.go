// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package k0s_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// kubeletResolv runs k0s-interim's kubelet_resolv on host (absent when
// empty) and returns the file it writes.
func kubeletResolv(t *testing.T, host string) string {
	t.Helper()
	b, err := os.ReadFile("k0s-interim")
	if err != nil {
		t.Fatal(err)
	}
	fn := regexp.MustCompile(`(?ms)^kubelet_resolv\(\) \{\n.*?^\}\n`).Find(b)
	if fn == nil {
		t.Fatal("k0s-interim has no kubelet_resolv function")
	}
	ip := regexp.MustCompile(`(?m)^node_ip=(\S+)`).FindSubmatch(b)
	if ip == nil {
		t.Fatal("k0s-interim sets no node_ip")
	}
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "host.conf"), filepath.Join(dir, "kubelet.conf")
	if host != "" {
		if err := os.WriteFile(src, []byte(host), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	script := "set -eu\nnode_ip=" + string(ip[1]) + "\n" + string(fn) + `kubelet_resolv "$1" "$2"` + "\n"
	if out, err := exec.Command("sh", "-c", script, "sh", src, dst).CombinedOutput(); err != nil { // #nosec G204 -- the repo's own script
		t.Fatalf("kubelet_resolv: %v: %s", err, out)
	}
	out, err := os.ReadFile(dst) // #nosec G304 -- the test's own file
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// CoreDNS runs with dnsPolicy Default and forwards to the servers in the
// kubelet's resolver file; with none it exits at start ("no valid upstream
// addresses found"). The box runs with no DNS server (spec 1), so then the
// kubelet's file names the node address, where nothing serves DNS: cluster
// names resolve and the rest fail.
func TestTheKubeletsResolverAlwaysNamesAServer(t *testing.T) {
	host := "# Written by sneakers-netd.\nnameserver 192.0.2.53\nnameserver 2001:db8::53\nsearch example.org\n"
	if got := kubeletResolv(t, host); got != host {
		t.Errorf("with the host's servers the kubelet gets %q; want the host's file %q", got, host)
	}
	for name, in := range map[string]string{
		"no server":    "# Written by sneakers-netd.\nsearch example.org\n",
		"empty file":   "\n",
		"missing file": "",
	} {
		got := kubeletResolv(t, in)
		var servers []string
		for _, l := range strings.Split(got, "\n") {
			if s, ok := strings.CutPrefix(l, "nameserver "); ok {
				servers = append(servers, s)
			}
		}
		if len(servers) != 1 || servers[0] != "198.18.0.1" {
			t.Errorf("%s: the kubelet's servers are %v; want the node address only", name, servers)
		}
		if strings.Contains(in, "search example.org") && !strings.Contains(got, "search example.org\n") {
			t.Errorf("%s: the host's search list went missing: %q", name, got)
		}
	}

	b, err := os.ReadFile("k0s-interim")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`kubelet_resolv /run/sneakers/resolv.conf /run/sneakers/k0s/resolv.conf`, "--resolv-conf=/run/sneakers/k0s/resolv.conf"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("k0s-interim doesn't have %q", want)
		}
	}
}
