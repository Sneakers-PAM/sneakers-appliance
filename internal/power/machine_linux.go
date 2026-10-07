// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package power

import (
	"context"
	"errors"
	"fmt"
	"os"

	log "github.com/Bugs5382/go-log"
	"golang.org/x/sys/unix"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/luks"
)

// Linux is the box: unmount(2), the static cryptsetup and reboot(2).
type Linux struct {
	// ESP is where init mounted the ESP.
	ESP string
	// Cryptsetup closes the LUKS mappings.
	Cryptsetup luks.Runner
	Logger     log.Logger
}

// Sync flushes every filesystem.
func (Linux) Sync() { unix.Sync() }

// CloseVolumes unmounts everything under /var/lib, deepest first, then
// closes the LUKS mappings behind it. A mount that won't go is detached
// lazily, so the box still goes down; its mapping then stays open and the
// error says so.
func (m Linux) CloseVolumes(ctx context.Context) error {
	b, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return err
	}
	targets, mappings := VolumeMounts(string(b))
	var errs []error
	for _, t := range targets {
		if err := unix.Unmount(t, 0); err != nil {
			m.Logger.Warn("power: unmount busy; detaching", log.F("target", t), log.F("error", err.Error()))
			if err := unix.Unmount(t, unix.MNT_DETACH); err != nil {
				errs = append(errs, fmt.Errorf("unmount %s: %w", t, err))
			}
		}
	}
	for _, name := range mappings {
		if _, stderr, err := m.Cryptsetup.Run(ctx, nil, "close", name); err != nil {
			errs = append(errs, fmt.Errorf("close %s: %w (%s)", name, err, stderr))
		}
	}
	return errors.Join(errs...)
}

// UnmountESP unmounts the ESP.
func (m Linux) UnmountESP() error {
	if err := unix.Unmount(m.ESP, 0); err != nil && !errors.Is(err, unix.EINVAL) {
		return err
	}
	return nil
}

// Reboot restarts the machine.
func (Linux) Reboot() error { return unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART) }

// PowerOff turns it off.
func (Linux) PowerOff() error { return unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF) }
