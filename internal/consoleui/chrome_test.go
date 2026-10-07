// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package consoleui_test

import (
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
)

func at() time.Time { return time.Date(2026, 10, 7, 18, 3, 0, 0, time.UTC) }

func TestTheBannerShowsOnlyReducedProtection(t *testing.T) {
	c := consoleui.Chrome{Version: "0.1.0", Phase: "normal", Now: at, Known: true, Protection: keycustody.Full(), Mode: keycustody.ModeTPM}
	if b := c.Banner(); len(b) != 0 {
		t.Fatalf("full: %v", b)
	}
	c.Protection, c.Mode = keycustody.Reduced(keycustody.ReasonSecureBootOff), keycustody.ModeKeyfile
	var text []string
	for _, l := range c.Banner() {
		text = append(text, l.String())
	}
	got := strings.Join(text, "\n")
	if !strings.HasPrefix(got, "!! Protection: reduced (Secure Boot off).") || !strings.Contains(got, ":8443 Status page") || len(text) != 3 {
		t.Fatalf("banner:\n%s", got)
	}
	c.Known = false
	if len(c.Banner()) != 0 {
		t.Fatal("a banner before init answered")
	}
}

func TestFooter(t *testing.T) {
	c := consoleui.Chrome{Version: "0.1.0", Phase: "firstboot", Now: at, NTP: consoleui.NTPUnsynced}
	if got := c.Footer(); got != "Sneakers-PAM 0.1.0 | firstboot | 2026-10-07 18:03 UTC | NTP not synced" {
		t.Fatal(got)
	}
}

func TestFingerprintLines(t *testing.T) {
	fp := strings.TrimSuffix(strings.Repeat("AB:", 32), ":")
	got := consoleui.FingerprintLines(fp)
	if len(got) != 2 || len(got[0]) != 47 || len(got[1]) != 47 {
		t.Fatalf("%q", got)
	}
}

func TestSteps(t *testing.T) {
	got := consoleui.Steps(3, []bool{true, true}).String()
	if got != "[x] 1 Network  [x] 2 Protection  [>] 3 Admin  [ ] 4 Recovery  [ ] 5 Sign-in" || len(got) > consoleui.Width {
		t.Fatal(got)
	}
}

func TestTheBannerFitsForEveryReason(t *testing.T) {
	for _, r := range []keycustody.Reason{keycustody.ReasonSecureBootOff, keycustody.ReasonNoSecureBootFirmware, keycustody.ReasonNoTPM} {
		for _, m := range []keycustody.Mode{keycustody.ModeTPM, keycustody.ModeKeyfile} {
			c := consoleui.Chrome{Known: true, Protection: keycustody.Reduced(r), Mode: m}
			for _, l := range c.Banner() {
				if l.Len() > consoleui.Width {
					t.Errorf("%s %s: %q is %d wide", r, m, l.String(), l.Len())
				}
			}
		}
	}
}
