// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package fixtures

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"oras.land/oras-go/v2"
	orasoci "oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry/remote"
)

// LabRegistry is a throwaway OCI registry (registry:2 in Docker) on
// loopback.
type LabRegistry struct {
	Host string
}

// StartRegistry runs a registry container for the test, or skips when
// Docker isn't available (failing instead when SNEAKERS_REQUIRE_TOOLS is
// set, as CI does).
func StartRegistry(t testing.TB) *LabRegistry {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		requireOrSkip(t, "docker isn't installed")
	}
	// stdout only: on a fresh host docker prints its pull progress on
	// stderr, and stdout's last line is the container ID.
	cmd := exec.Command("docker", "run", "-d", "--rm", "-p", "127.0.0.1::5000", "registry:2")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		requireOrSkip(t, "can't start registry:2: "+strings.TrimSpace(stderr.String()))
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	id := strings.TrimSpace(lines[len(lines)-1])
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() }) // #nosec G204 -- the container this test started
	port, err := exec.Command("docker", "port", id, "5000/tcp").Output()   // #nosec G204 -- as above
	must(t, err)
	host := strings.TrimSpace(strings.Split(strings.TrimSpace(string(port)), "\n")[0])
	r := &LabRegistry{Host: host}
	deadline := time.Now().Add(30 * time.Second)
	for {
		repo, err := remote.NewRepository(host + "/probe")
		must(t, err)
		repo.PlainHTTP = true
		if err := repo.Tags(context.Background(), "", func([]string) error { return nil }); err == nil || !strings.Contains(err.Error(), "connect") {
			return r
		}
		if time.Now().After(deadline) {
			t.Fatalf("registry at %s didn't come up", host)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// Ref is the reference of repo:tag on the registry.
func (r *LabRegistry) Ref(repoTag string) string { return r.Host + "/" + repoTag }

// Push copies the fixture layout in dir, with its signature, to repo:tag.
func (r *LabRegistry) Push(t testing.TB, dir, repoTag string) {
	t.Helper()
	src, err := orasoci.New(dir)
	must(t, err)
	name, tag, _ := strings.Cut(repoTag, ":")
	dst, err := remote.NewRepository(r.Host + "/" + name)
	must(t, err)
	dst.PlainHTTP = true
	_, err = oras.ExtendedCopy(context.Background(), src, Version, dst, tag, oras.DefaultExtendedCopyOptions)
	must(t, err)
}

func requireOrSkip(t testing.TB, why string) {
	t.Helper()
	if os.Getenv("SNEAKERS_REQUIRE_TOOLS") != "" {
		t.Fatal(why + " and SNEAKERS_REQUIRE_TOOLS is set")
	}
	t.Skip(why)
}
