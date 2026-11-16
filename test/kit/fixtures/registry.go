// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package fixtures

import (
	"context"
	"fmt"
	"net/http"
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
	if err := waitRegistry(context.Background(), host, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	return r
}

// waitRegistry returns once the registry answers GET /v2/ with 200. A port
// that is open is not enough: docker's port proxy accepts the connection and
// drops it (EOF) until the registry inside the container listens, and a
// request that lands then fails with an EOF the caller can't retry.
func waitRegistry(ctx context.Context, host string, bound time.Duration) error {
	deadline := time.Now().Add(bound)
	var last error
	for {
		last = probeRegistry(ctx, host)
		if last == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("registry at %s didn't come up: %w", host, last)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func probeRegistry(ctx context.Context, host string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+"/v2/", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET /v2/: %s", resp.Status)
	}
	return nil
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
