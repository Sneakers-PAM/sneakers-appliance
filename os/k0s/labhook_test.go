// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package k0s_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const labHook = "../../build/lab/overlay/usr/libexec/sneakers/lab-hook"

// After a power loss the kubelet restarts the old pods in place before
// the box's phase loop can quiesce them, so the first Ready hello pod is
// the old one. The lab hook samples the phase pods only once the box says
// running (edgefall's /_box/state on its loopback listener), which it
// says only after the phase loop brought every phase up.
func TestTheLabHookSamplesThePhasesOnceTheBoxRuns(t *testing.T) {
	b, err := os.ReadFile(labHook)
	if err != nil {
		t.Fatal(err)
	}
	hook := string(b)
	running := strings.Index(hook, `wait_for "box running" box_running`)
	pods := strings.Index(hook, `say "phase pods:`)
	if running < 0 || pods < 0 || running > pods {
		t.Fatalf("the hook prints the phase pods before it waits for the box to run (box running at %d, phase pods at %d)", running, pods)
	}
	fn := regexp.MustCompile(`(?ms)^box_running\(\) \{\n.*?^\}\n`).FindString(hook)
	if fn == "" {
		t.Fatal("the lab hook has no box_running function")
	}
	if _, err := exec.LookPath("nc"); err != nil {
		t.Skip("no nc on this host")
	}
	state := `{"state":"starting"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_box/state" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(state))
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if _, err := strconv.Atoi(port); err != nil {
		t.Fatal(err)
	}
	ask := func() bool {
		script := "set -u\n" + fn + `box_running "$1" "$2"` + "\n"
		return exec.Command("sh", "-c", script, "sh", host, port).Run() == nil // #nosec G204 -- the repo's own script
	}
	if ask() {
		t.Fatal("box_running says running while the box is starting")
	}
	state = `{"state":"running","brand":{}}`
	if !ask() {
		t.Fatal("box_running doesn't say running")
	}
}
