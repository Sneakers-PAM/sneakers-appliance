// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package console_test

import (
	"os"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/console"
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
