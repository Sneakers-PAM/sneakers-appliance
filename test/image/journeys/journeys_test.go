// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

// Package journeys_test boots the box the sign-off browser journeys
// (test/e2e/journeys, docs/testing.md#the-browser-journeys) run against,
// and runs them in headless Chromium: a new box from the lab raw disk with
// the :8443 pages, on QEMU's user network as a VMware VM sees it (VGA, keys
// enrolled with Secure Boot off, no TPM). The person at the console types
// the boot's own choices; everything after that is the browser's.
//
// The browser goes to the address the console shows, the box's DHCP lease
// (box), through a proxy the driver runs: it takes CONNECT to that address's
// 8443 and 443 only, and passes each to QEMU's forward of that port on the
// runner's loopback. TLS runs end to end through it, so the browser checks
// the box's certificate itself. (A forward bound to the lease's own address
// on the runner doesn't work: QEMU would hand the box connections from its
// own address.) The box's mail relay is the runner's mail catcher, through
// a guest forward from mailRelay. The driver serves the console's display
// to the journeys, read off QEMU, so they read the setup code and the
// certificate fingerprint where a person reads them, and it starts the box
// again whenever it restarts (QEMU runs with -no-reboot).
package journeys_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/screens"
	"github.com/Sneakers-PAM/sneakers-appliance/test/image/harness"
)

const (
	// box is the address QEMU's user network leases the first guest, the
	// one the console shows.
	box = "10.0.2.15" // scrub:allow=private-ip -- QEMU's user network
	// mailRelay is where the box sends mail: QEMU hands each connection to
	// the runner's mail catcher.
	mailRelay = "10.0.2.100:2525" // scrub:allow=private-ip -- QEMU's user network
	// maxBoots bounds the restarts: setup's own, and one more.
	maxBoots = 3
)

// env is what the workflow hands the driver (build/journeys/build.sh and
// build/journeys/mail.sh write it).
type env struct {
	image, keys, product, version string
	mailSMTP, mailAPI, mailCA     string
	journeys                      string
	// adminPort and productPort are QEMU's forwards of the box's 8443
	// and 443 on the runner's loopback.
	adminPort, productPort int
}

func need(t *testing.T) env {
	t.Helper()
	e := env{
		image: os.Getenv("SNEAKERS_IMAGE"), keys: os.Getenv("SNEAKERS_KEYS"),
		product: os.Getenv("SNEAKERS_JOURNEYS_PRODUCT"), version: os.Getenv("SNEAKERS_JOURNEYS_PRODUCT_VERSION"),
		mailSMTP: os.Getenv("SNEAKERS_JOURNEYS_MAIL_SMTP"), mailAPI: os.Getenv("SNEAKERS_JOURNEYS_MAIL_API"),
		mailCA: os.Getenv("SNEAKERS_JOURNEYS_MAIL_CA"),
	}
	// The image suite's own run builds no real product and runs no mail
	// catcher, so the journeys skip there.
	if e.product == "" || e.version == "" || e.mailSMTP == "" || e.mailAPI == "" || e.mailCA == "" {
		t.Skip("SNEAKERS_JOURNEYS_* name the journeys' product bundle and mail catcher (build/journeys)")
	}
	abs, err := filepath.Abs(filepath.Join("..", "..", "e2e", "journeys"))
	if err != nil {
		t.Fatal(err)
	}
	e.journeys = abs
	harness.Need(t, []string{"npx", "socat"}, e.image, e.keys, e.product, e.mailCA, filepath.Join(abs, "node_modules"))
	e.adminPort, e.productPort = freePort(t), freePort(t)
	return e
}

func (e env) opts(disk harness.Disk) harness.Options {
	return harness.Options{
		SecureBoot: harness.OffWithKeys, Keys: e.keys, MemMiB: 8192, CPUs: 4, Timeout: 4 * time.Hour,
		Disks:    []harness.Disk{disk},
		HostFwd:  []string{fmt.Sprintf("tcp:127.0.0.1:%d-:8443", e.adminPort), fmt.Sprintf("tcp:127.0.0.1:%d-:443", e.productPort)},
		GuestFwd: []string{"tcp:" + mailRelay + "-cmd:socat - TCP:" + e.mailSMTP},
	}
}

// display serves the running box's display to the journeys: /screen as
// text, /screenshot as a PNG. While the box is down it answers 503.
type display struct {
	mu sync.Mutex
	vm *harness.VM
}

func (d *display) set(vm *harness.VM) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.vm = vm
}

func (d *display) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.vm == nil {
		http.Error(w, "the box is restarting", http.StatusServiceUnavailable)
		return
	}
	switch r.URL.Path {
	case "/screen":
		rows, err := d.vm.ReadScreen()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"text": harness.ScreenText(rows)})
	case "/screenshot":
		ppm, err := d.vm.Screendump()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		img, err := decodePPM(ppm)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		_ = png.Encode(w, img)
	default:
		http.NotFound(w, r)
	}
}

// keepConsole writes a boot's serial console where the job collects its
// logs (SNEAKERS_LOG_DIR), when it names one.
func keepConsole(t *testing.T, vm *harness.VM, n int) {
	dir := os.Getenv("SNEAKERS_LOG_DIR")
	if dir == "" {
		return
	}
	t.Cleanup(func() {
		_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("journeys-boot%d.log", n)), []byte(vm.Console()), 0o600) // #nosec G703 -- the job's own log directory
	})
}

func TestTheSignOffJourneys(t *testing.T) {
	e := need(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Hour)
	defer cancel()

	boots := 1
	vm := harness.Boot(t, e.opts(harness.Disk{Image: e.image}))
	keepConsole(t, vm, boots)
	// The boot's own choices, typed at the console as the person setting
	// the box up does; first boot then asks nothing.
	vm.ExpectScreen(`type "`+screens.TypedNoSecureBoot+`" and press Enter`, 5*time.Minute)
	vm.Press(screens.TypedNoSecureBoot + "\r")
	vm.ExpectScreen(`Press Enter to continue`, 2*time.Minute)
	vm.Press("\r")
	vm.ExpectScreen(`Open this address in your browser: .*https://`+regexp.QuoteMeta(box)+`:8443`, 5*time.Minute)

	shown := &display{vm: vm}
	consoleAddr := serve(t, shown)
	proxyAddr := serve(t, boxProxy{routes: map[string]string{
		box + ":8443": fmt.Sprintf("127.0.0.1:%d", e.adminPort),
		box + ":443":  fmt.Sprintf("127.0.0.1:%d", e.productPort),
	}})

	state := filepath.Join(t.TempDir(), "journeys-state.json")
	cmd := exec.CommandContext(ctx, "npx", "playwright", "test") // #nosec G204 -- test-only, the repository's own journeys
	cmd.Dir = e.journeys
	cmd.Env = append(os.Environ(),
		"CI=1",
		"JOURNEYS_BOX="+box,
		"JOURNEYS_CONSOLE=http://"+consoleAddr,
		"JOURNEYS_PROXY=http://"+proxyAddr,
		"JOURNEYS_STATE="+state,
		"JOURNEYS_PRODUCT_BUNDLE="+e.product,
		"JOURNEYS_PRODUCT_VERSION="+e.version,
		"JOURNEYS_MAIL_RELAY="+mailRelay,
		"JOURNEYS_MAIL_API="+e.mailAPI,
		"JOURNEYS_MAIL_CA="+e.mailCA,
	)
	var out bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &out)
	cmd.Stderr = cmd.Stdout
	start := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	for {
		select {
		case err := <-done:
			t.Logf("the journeys ran for %s over %d boots", time.Since(start).Round(time.Second), boots)
			if err != nil {
				t.Fatalf("the journeys failed: %v (the Playwright report and traces are in the journeys artifact)\n%s", err, tailLines(out.String(), 60))
			}
			return
		case <-vm.Exited():
			shown.set(nil)
			if boots == maxBoots {
				cancel()
				<-done
				t.Fatalf("the box stopped %d times; the journeys expect setup's restart only", boots)
			}
			boots++
			t.Logf("the box restarted after %s; boot %d", time.Since(start).Round(time.Second), boots)
			vm = harness.Boot(t, e.opts(harness.Disk{Image: vm.Disk(0), Move: true}))
			keepConsole(t, vm, boots)
			shown.set(vm)
		}
	}
}

func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
