// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package console_test

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/console"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
)

// The console's screens are laid out for the large font: the kernel has
// it built in, the UKI's command line selects it, and the small font the
// console falls back to is built in too.
func TestTheKernelHasAndSelectsTheLargeFont(t *testing.T) {
	cfg, err := os.ReadFile("../../os/kernel/config-base")
	if err != nil {
		t.Fatal(err)
	}
	for _, opt := range []string{"CONFIG_FONTS=y", "CONFIG_FONT_TER16x32=y", "CONFIG_FONT_8x16=y", "CONFIG_FRAMEBUFFER_CONSOLE=y"} {
		if !strings.Contains("\n"+string(cfg), "\n"+opt+"\n") {
			t.Errorf("os/kernel/config-base lacks %s", opt)
		}
	}
	uki, err := os.ReadFile("../../build/uki/assemble.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(uki), " fbcon=font:TER16x32 ") {
		t.Error("the UKI command line doesn't select fbcon=font:TER16x32")
	}
	if console.SmallFont != "VGA8x16" {
		t.Errorf("the fallback is %q, not the built-in 8x16", console.SmallFont)
	}
}

// The VT's default palette is VGA's, whose "orange" is brown (#AA5500).
// The UKI's command line sets the VT palette to the approved one, so the
// screen shows the brand colours; a serial line keeps its own.
func TestTheUKISetsTheApprovedPalette(t *testing.T) {
	uki, err := os.ReadFile("../../build/uki/assemble.sh")
	if err != nil {
		t.Fatal(err)
	}
	var got [16]string
	for _, c := range []string{"red", "grn", "blu"} {
		m := regexp.MustCompile(`vt\.default_` + c + `=([0-9a-fx,]+)`).FindSubmatch(uki)
		if m == nil {
			t.Fatalf("the UKI command line doesn't set vt.default_%s", c)
		}
		vals := strings.Split(string(m[1]), ",")
		if len(vals) != 16 {
			t.Fatalf("vt.default_%s has %d values, not 16", c, len(vals))
		}
		for i, v := range vals {
			n, err := strconv.ParseUint(v, 0, 8)
			if err != nil {
				t.Fatalf("vt.default_%s[%d] = %q: %v", c, i, v, err)
			}
			got[i] += fmt.Sprintf("%02X", n)
		}
	}
	if got != tui.Palette {
		t.Fatalf("the VT palette is\n%v, not the approved\n%v", got, tui.Palette)
	}
	if tui.Palette[3] != "E8742A" {
		t.Fatalf("the accent slot is #%s, not the approved orange #E8742A", tui.Palette[3])
	}
}
