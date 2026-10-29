// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package vports gives each named virtio-serial port its
// /dev/virtio-ports/<name> link, as udev does on a distribution, so a
// service can wait for a port by name: the QEMU guest agent's
// org.qemu.guest_agent.0 (spec 1 Section 2.8). The box has no udev, so
// init keeps the links in step with /sys/class/virtio-ports while it runs.
package vports

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
)

// The kernel's class directory and the device directory init links into.
const (
	SysClass = "/sys/class/virtio-ports"
	DevDir   = "/dev"
)

// Every is how often Watch looks again: Proxmox and QEMU can hot-plug a
// port, and the host names a port a moment after the kernel sees it.
const Every = 2 * time.Second

// Link makes dev/virtio-ports/<name> point at ../<port> for every port in
// sys with a name, and removes the links whose port is gone or renamed.
// Without the class directory there's nothing to link.
func Link(sys, dev string) error {
	entries, err := os.ReadDir(sys)
	if errors.Is(err, fs.ErrNotExist) {
		entries = nil
	} else if err != nil {
		return err
	}
	want := map[string]string{}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(sys, e.Name(), "name")) // #nosec G304 -- the kernel's class directory
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(b))
		if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') {
			continue
		}
		want[name] = "../" + e.Name()
	}
	dir := filepath.Join(dev, "virtio-ports")
	have, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if len(want) == 0 && len(have) == 0 {
		return nil
	}
	for _, h := range have {
		p := filepath.Join(dir, h.Name())
		if cur, err := os.Readlink(p); err == nil && cur == want[h.Name()] {
			delete(want, h.Name())
			continue
		}
		if err := os.Remove(p); err != nil {
			return err
		}
	}
	if len(want) == 0 {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- /dev/virtio-ports is world-readable, as udev makes it
		return err
	}
	for name, target := range want {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

// Watch runs Link every Every until ctx ends, logging each change of the
// set of linked ports and each error once.
func Watch(ctx context.Context, lg log.Logger) {
	var last, lastErr string
	t := time.NewTicker(Every)
	defer t.Stop()
	for {
		if err := Link(SysClass, DevDir); err != nil {
			if err.Error() != lastErr {
				lg.Error(err, "vports: the virtio port links weren't made")
				lastErr = err.Error()
			}
		} else {
			lastErr = ""
			if now := linked(); now != last {
				lg.Info("vports: virtio ports linked", log.F("ports", now))
				last = now
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func linked() string {
	entries, _ := os.ReadDir(filepath.Join(DevDir, "virtio-ports"))
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return strings.Join(names, ",")
}
