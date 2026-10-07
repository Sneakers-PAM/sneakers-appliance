// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package harness boots appliance disk images in QEMU (q35, OVMF with
// Secure Boot, swtpm) for the image suite, and reads their serial console.
// A missing tool skips with its name (failing instead when
// SNEAKERS_REQUIRE_TOOLS is set, as CI does).
package harness

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// SecureBoot is the firmware's starting state.
type SecureBoot int

// The firmware states.
const (
	// Enrolled: the run's lab PK, KEK and db are in the vars store and
	// Secure Boot enforces from the first instruction.
	Enrolled SecureBoot = iota
	// SetupMode: an empty vars store; the box enrols itself.
	SetupMode
	// Off: the Secure Boot firmware with an empty store and enforcement
	// never turned on.
	Off
	// OffWithKeys: keys enrolled (the run's lab keys, standing in for a
	// vendor's) but enforcement off, so the firmware isn't in Setup Mode:
	// a VMware VM with Secure Boot turned off in its settings.
	OffWithKeys
)

// Disk is one disk attached to the VM.
type Disk struct {
	// Image is copied before the boot, so the original stays pristine.
	Image   string
	SizeGiB int
}

// Options shape one boot.
type Options struct {
	SecureBoot SecureBoot
	TPM        bool
	Disks      []Disk
	// Keys is the lab key directory (build/keys/lab-keys.sh) for Enrolled.
	Keys    string
	MemMiB  int
	Timeout time.Duration
}

// Paths of the pinned firmware (Ubuntu's ovmf package in CI).
var (
	OVMFCode = envOr("SNEAKERS_OVMF_CODE", "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd")
	OVMFVars = envOr("SNEAKERS_OVMF_VARS", "/usr/share/OVMF/OVMF_VARS_4M.fd")
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// Need skips (or fails, under SNEAKERS_REQUIRE_TOOLS) unless every tool is
// on PATH and every file exists.
func Need(t testing.TB, tools []string, files ...string) {
	t.Helper()
	var missing []string
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			missing = append(missing, f)
		}
	}
	if len(missing) == 0 {
		return
	}
	msg := "missing " + strings.Join(missing, ", ")
	if os.Getenv("SNEAKERS_REQUIRE_TOOLS") != "" {
		t.Fatal(msg + " and SNEAKERS_REQUIRE_TOOLS is set")
	}
	t.Skip(msg)
}

// VM is a running boot.
type VM struct {
	t      testing.TB
	cmd    *exec.Cmd
	serial string
	cancel context.CancelFunc
	dir    string
	done   chan struct{}
	in     string
}

// Boot starts QEMU with o and returns once it's running.
func Boot(t testing.TB, o Options) *VM {
	t.Helper()
	Need(t, []string{"qemu-system-x86_64", "swtpm", "virt-fw-vars", "qemu-img"}, OVMFCode, OVMFVars)
	dir := t.TempDir()
	vars := filepath.Join(dir, "vars.fd")
	switch o.SecureBoot {
	case Enrolled:
		owner := "5d4c8e4b-3b9b-4b58-9e2c-0d7e1f2a3b4c"
		run(t, "virt-fw-vars", "--input", OVMFVars, "--output", vars,
			"--set-pk", owner, filepath.Join(o.Keys, "PK.crt"),
			"--add-kek", owner, filepath.Join(o.Keys, "KEK.crt"),
			"--add-db", owner, filepath.Join(o.Keys, "db.crt"),
			"--secure-boot")
	case OffWithKeys:
		owner := "5d4c8e4b-3b9b-4b58-9e2c-0d7e1f2a3b4c"
		run(t, "virt-fw-vars", "--input", OVMFVars, "--output", vars,
			"--set-pk", owner, filepath.Join(o.Keys, "PK.crt"),
			"--add-kek", owner, filepath.Join(o.Keys, "KEK.crt"),
			"--add-db", owner, filepath.Join(o.Keys, "db.crt"),
			// OVMF enforces as soon as a PK is enrolled unless this is off.
			"--set-false", "SecureBootEnable")
	default:
		copyFile(t, OVMFVars, vars)
	}
	mem := o.MemMiB
	if mem == 0 {
		mem = 2048
	}
	timeout := o.Timeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	serial := filepath.Join(dir, "serial.log")
	// The serial line is a pair of FIFOs (QEMU's pipe chardev): the
	// output is copied into serial.log, and Type writes the input.
	ser := filepath.Join(dir, "ser")
	for _, f := range []string{ser + ".in", ser + ".out"} {
		if err := unix.Mkfifo(f, 0o600); err != nil {
			cancel()
			t.Fatal(err)
		}
	}
	// O_RDWR so the open doesn't wait for QEMU; the copy ends when QEMU
	// has exited and this descriptor is closed.
	pipe, err := os.OpenFile(ser+".out", os.O_RDWR, 0) // #nosec G304 -- the VM's FIFO
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	args := []string{
		"-machine", "q35,smm=on", "-m", fmt.Sprint(mem), "-smp", "2", "-nographic", "-no-reboot",
		"-global", "driver=cfi.pflash01,property=secure,value=on",
		"-drive", "if=pflash,format=raw,unit=0,readonly=on,file=" + OVMFCode,
		"-drive", "if=pflash,format=raw,unit=1,file=" + vars,
		"-chardev", "pipe,id=ser0,path=" + ser, "-serial", "chardev:ser0", "-monitor", "none",
		"-netdev", "user,id=n0,restrict=on", "-device", "virtio-net-pci,netdev=n0",
	}
	if _, err := os.Stat("/dev/kvm"); err == nil {
		args = append(args, "-accel", "kvm", "-cpu", "host")
	} else {
		args = append(args, "-accel", "tcg")
	}
	if o.TPM {
		sock := filepath.Join(dir, "swtpm.sock")
		state := filepath.Join(dir, "tpm")
		if err := os.Mkdir(state, 0o700); err != nil {
			t.Fatal(err)
		}
		tpm := exec.CommandContext(ctx, "swtpm", "socket", "--tpm2", "--tpmstate", "dir="+state, "--ctrl", "type=unixio,path="+sock) // #nosec G204 -- test-only, fixed tool
		if err := tpm.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tpm.Process.Kill(); _ = tpm.Wait() })
		waitFor(t, sock)
		args = append(args, "-chardev", "socket,id=chrtpm,path="+sock, "-tpmdev", "emulator,id=tpm0,chardev=chrtpm", "-device", "tpm-tis,tpmdev=tpm0")
	}
	for i, d := range o.Disks {
		img := filepath.Join(dir, fmt.Sprintf("disk%d.raw", i))
		if d.Image != "" {
			run(t, "cp", "--sparse=always", d.Image, img)
		} else {
			run(t, "qemu-img", "create", "-f", "raw", img, fmt.Sprintf("%dG", max(d.SizeGiB, 1)))
		}
		if d.Image != "" && d.SizeGiB > 0 {
			run(t, "qemu-img", "resize", "-f", "raw", img, fmt.Sprintf("%dG", d.SizeGiB))
		}
		args = append(args, "-drive", fmt.Sprintf("if=none,id=d%d,format=raw,file=%s", i, img), "-device", fmt.Sprintf("virtio-blk-pci,drive=d%d", i))
	}
	cmd := exec.CommandContext(ctx, "qemu-system-x86_64", args...) // #nosec G204 -- test-only, fixed tool
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	vm := &VM{t: t, cmd: cmd, serial: serial, cancel: cancel, dir: dir, done: make(chan struct{}), in: ser + ".in"}
	copied := make(chan struct{})
	go func() {
		defer close(copied)
		out, err := os.OpenFile(serial, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- the test's own log
		if err != nil {
			return
		}
		defer func() { _ = out.Close() }()
		_, _ = io.Copy(out, pipe)
	}()
	go func() {
		_ = cmd.Wait()
		// Let the copy drain what QEMU wrote last before it's closed.
		time.Sleep(500 * time.Millisecond)
		_ = pipe.Close()
		<-copied
		close(vm.done)
	}()
	t.Cleanup(func() {
		cancel()
		<-vm.done
		if t.Failed() {
			b, _ := os.ReadFile(serial) // #nosec G304 -- the test's own log
			t.Logf("serial console:\n%s\nqemu stderr:\n%s", tail(b, 200), stderr.String())
		}
		if s := os.Getenv("GITHUB_STEP_SUMMARY"); s != "" {
			b, _ := os.ReadFile(serial)                                               // #nosec G304 -- as above
			if f, err := os.OpenFile(s, os.O_APPEND|os.O_WRONLY, 0o600); err == nil { // #nosec G304 G703 -- the CI summary file GitHub names
				_, _ = fmt.Fprintf(f, "\n<details><summary>%s serial console</summary>\n\n```\n%s\n```\n</details>\n", t.Name(), tail(b, 80))
				_ = f.Close()
			}
		}
	})
	return vm
}

// Type sends s on the serial line, as typed at the console.
func (vm *VM) Type(s string) {
	vm.t.Helper()
	f, err := os.OpenFile(vm.in, os.O_WRONLY, 0) // #nosec G304 -- the VM's FIFO
	if err != nil {
		vm.t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(s); err != nil {
		vm.t.Fatal(err)
	}
}

// ansi matches the colour codes init's console log carries.
var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// Expect waits until the serial console shows re, or fails the test. The
// console is matched without its colour codes.
func (vm *VM) Expect(re string, timeout time.Duration) string {
	vm.t.Helper()
	rx := regexp.MustCompile(re)
	deadline := time.Now().Add(timeout)
	for {
		if m := rx.FindString(vm.Console()); m != "" {
			return m
		}
		if time.Now().After(deadline) {
			vm.t.Fatalf("serial console never showed %q in %s", re, timeout)
		}
		if vm.exited() {
			if m := rx.FindString(vm.Console()); m != "" {
				return m
			}
			vm.t.Fatalf("QEMU exited before the serial console showed %q", re)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (vm *VM) exited() bool {
	select {
	case <-vm.done:
		return true
	default:
		return false
	}
}

// Console is the serial console so far, without colour codes.
func (vm *VM) Console() string {
	b, _ := os.ReadFile(vm.serial) // #nosec G304 -- the VM's own log
	return ansi.ReplaceAllString(string(b), "")
}

// Disk is the path of the VM's copy of disk i. Once the VM has exited it
// holds what the guest wrote, and a later Boot can take it as its Image.
func (vm *VM) Disk(i int) string { return filepath.Join(vm.dir, fmt.Sprintf("disk%d.raw", i)) }

// Stop powers the VM off (QEMU is killed) and waits for it to go. Its disk
// keeps what the guest had synced.
func (vm *VM) Stop() {
	vm.cancel()
	<-vm.done
}

// WaitExit waits for QEMU to exit (a guest reboot, with -no-reboot, or a
// power-off), or fails the test.
func (vm *VM) WaitExit(timeout time.Duration) {
	vm.t.Helper()
	select {
	case <-vm.done:
	case <-time.After(timeout):
		vm.t.Fatalf("QEMU didn't exit within %s", timeout)
	}
}

// The console lines that mean init gave up or a service keeps failing.
var (
	initFatal = regexp.MustCompile(`init: fatal|Kernel panic|Attempted to kill init`)
	restarted = regexp.MustCompile(`services: exited .*restart=true service=([A-Za-z0-9_-]+)`)
)

// CrashLoopRestarts is how many restarts within a Stable window count as a
// crash loop.
const CrashLoopRestarts = 3

// Stable watches the console for window and fails the test if init stops
// (its fatal line or a kernel panic), QEMU exits, or a service is
// restarted CrashLoopRestarts times or more. known maps a service to the
// reason it's expected to crash-loop on this image; it's logged, not
// failed, and a known service that doesn't loop fails, so the entry is
// removed once its cause is fixed.
func (vm *VM) Stable(window time.Duration, known map[string]string) {
	vm.t.Helper()
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		if vm.exited() {
			vm.t.Fatalf("QEMU exited during the stability window")
		}
		if m := initFatal.FindString(vm.Console()); m != "" {
			vm.t.Fatalf("init stopped: the console shows %q", m)
		}
		time.Sleep(time.Second)
	}
	counts := map[string]int{}
	for _, m := range restarted.FindAllStringSubmatch(vm.Console(), -1) {
		counts[m[1]]++
	}
	for name, n := range counts {
		if n < CrashLoopRestarts {
			continue
		}
		if why, ok := known[name]; ok {
			vm.t.Logf("%s restarted %d times in %s, as expected on this image: %s", name, n, window, why)
			continue
		}
		vm.t.Errorf("%s is crash-looping: restarted %d times in %s", name, n, window)
	}
	for name, why := range known {
		if counts[name] < CrashLoopRestarts {
			vm.t.Errorf("%s was expected to crash-loop (%s) but restarted %d times; drop it from the known list", name, why, counts[name])
		}
	}
}

func tail(b []byte, lines int) string {
	ls := strings.Split(string(b), "\n")
	if len(ls) > lines {
		ls = ls[len(ls)-lines:]
	}
	return strings.Join(ls, "\n")
}

func run(t testing.TB, name string, args ...string) {
	t.Helper()
	if b, err := exec.Command(name, args...).CombinedOutput(); err != nil { // #nosec G204 -- test-only, fixed tools
		t.Fatalf("%s: %v\n%s", name, err, b)
	}
}

func copyFile(t testing.TB, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from) // #nosec G304 -- the firmware file
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o600); err != nil { // #nosec G703 -- a file in the test's own temp directory
		t.Fatal(err)
	}
}

func waitFor(t testing.TB, p string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(p); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s never appeared", p)
}
