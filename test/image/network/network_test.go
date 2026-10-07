// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

// Package network_test is the image suite's run of netd: a first boot on
// QEMU's user network gets its address from QEMU's DHCP server with no
// setting made, and SSH stays closed until the first-boot SSH step.
package network_test

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/screens"
	"github.com/Sneakers-PAM/sneakers-appliance/test/image/harness"
)

const (
	prompt  = `type "` + screens.TypedNoSecureBoot + `" and press Enter`
	keyfile = `Press Enter to continue`
	booted  = `services: entering phase phase=firstboot`
	// QEMU's user network hands the first guest its first lease. netd logs
	// it, and the setup wizard, which owns the console once it runs, shows
	// it; whichever comes first is on the serial line.
	leased = `10\.0\.2\.15/24` // scrub:allow=private-ip -- QEMU's user network
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

// sshBanner reads what answers on the forwarded port: QEMU accepts the
// connection itself, so a closed guest port shows as no banner.
func sshBanner(addr string) string {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return ""
	}
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, _ := bufio.NewReader(c).ReadString('\n')
	return line
}

func TestFirstBootGetsADHCPAddressAndKeepsSSHClosed(t *testing.T) {
	img, keys := os.Getenv("SNEAKERS_IMAGE"), os.Getenv("SNEAKERS_KEYS")
	harness.Need(t, nil, img, keys)
	port := freePort(t)
	vm := harness.Boot(t, harness.Options{
		SecureBoot: harness.OffWithKeys, Keys: keys, Disks: []harness.Disk{{Image: img}}, NoVGA: true,
		HostFwd: []string{fmt.Sprintf("tcp:127.0.0.1:%d-:22", port)},
	})
	vm.Expect(prompt, 5*time.Minute)
	vm.Type(screens.TypedNoSecureBoot + "\r")
	vm.Expect(keyfile, 2*time.Minute)
	vm.Type("\r")
	vm.Expect(booted, 3*time.Minute)
	vm.Expect(leased, 2*time.Minute)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for i := 0; i < 3; i++ {
		if b := sshBanner(addr); strings.HasPrefix(b, "SSH-") {
			t.Fatalf("SSH answered before the first-boot SSH step: %q", b)
		}
	}
	vm.Stable(30*time.Second, nil)
}
