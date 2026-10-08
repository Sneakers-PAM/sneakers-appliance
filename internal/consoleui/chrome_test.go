// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package consoleui_test

import (
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
)

func at() time.Time { return time.Date(2026, 10, 7, 18, 3, 0, 0, time.UTC) }

// The protection is one line: the level in its status colour, then the
// reason in plain words.
func TestProtectionLine(t *testing.T) {
	cases := []struct {
		p     keycustody.Protection
		m     keycustody.Mode
		known bool
		want  string
		style tui.Style
	}{
		{keycustody.Full(), keycustody.ModeTPM, true, "Protection  FULL  Secure Boot on, key in the TPM", tui.OK},
		{keycustody.Reduced(keycustody.ReasonSecureBootOff), keycustody.ModeTPM, true, "Protection  REDUCED  Secure Boot off, key in the TPM", tui.Warn},
		{keycustody.Reduced(keycustody.ReasonNoSecureBootFirmware), keycustody.ModeKeyfile, true, "Protection  REDUCED  no TPM, no Secure Boot", tui.Warn},
		{keycustody.Reduced(keycustody.ReasonNoTPM), keycustody.ModeKeyfile, true, "Protection  REDUCED  no TPM, Secure Boot on", tui.Warn},
		{keycustody.Protection{}, "", false, "Protection  UNKNOWN  the boot hasn't answered yet", tui.Warn},
	}
	for _, c := range cases {
		ch := consoleui.Chrome{Known: c.known, Protection: c.p, Mode: c.m}
		l := ch.ProtectionLine(12)
		if got := strings.Join(strings.Fields(l.String()), " "); got != strings.Join(strings.Fields(c.want), " ") {
			t.Errorf("%v %s: %q, want %q", c.p, c.m, l.String(), c.want)
		}
		if l[1].Style != c.style {
			t.Errorf("%v: level style %v", c.p, l[1].Style)
		}
		if l.Len() > tui.Width {
			t.Errorf("%v: %d wide", c.p, l.Len())
		}
	}
}

// Fingerprints read aloud in groups of four, eight groups to a line.
func TestFingerprintGroups(t *testing.T) {
	fp := strings.TrimSuffix(strings.Repeat("7C:2E:", 16), ":")
	got := consoleui.FingerprintGroups(fp)
	if len(got) != 2 || got[0] != "7C2E 7C2E 7C2E 7C2E 7C2E 7C2E 7C2E 7C2E" || got[1] != got[0] {
		t.Fatalf("%q", got)
	}
	if got := consoleui.FingerprintGroups(""); got != nil {
		t.Fatalf("empty: %q", got)
	}
}

func TestSSHFingerprintGroups(t *testing.T) {
	got := consoleui.SSHFingerprintGroups("SHA256:ysknevuNI/Ng13w+vvxlQW6FcH76LnuVdAfLHqOrZRw")
	want := []string{"SHA256:yskn evuN I/Ng 13w+ vvxl QW6F", "       cH76 LnuV dAfL HqOr ZRw"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("%q", got)
	}
}

func TestClock(t *testing.T) {
	c := consoleui.Chrome{Now: at, NTP: consoleui.NTPSynced}
	if l := c.ClockLine(12); !strings.Contains(l.String(), "OK") || !strings.Contains(l.String(), "synced 18:03 UTC") {
		t.Fatalf("%q", l.String())
	}
	c.NTP = consoleui.NTPUnsynced
	if l := c.ClockLine(12); !strings.Contains(l.String(), "UNSYNCED") || l[1].Style != tui.Warn {
		t.Fatalf("%q", l.String())
	}
}

func TestPageCarriesTheWordmark(t *testing.T) {
	c := consoleui.Chrome{Version: "0.1.0", Info: "slot A  1 node"}
	p := c.Page([]tui.Line{tui.Text("body")}, nil, "")
	if p.Name != "Sneakers-PAM appliance" || p.Version != "0.1.0" || p.Info != "slot A  1 node" || p.Big {
		t.Fatalf("%+v", p)
	}
	if b := c.BigPage(nil); !b.Big {
		t.Fatal("not big")
	}
}

// A code says how long it has left in whole minutes, not counting the one
// running: a fresh 60-minute code says 59.
func TestExpires(t *testing.T) {
	for left, want := range map[time.Duration]string{time.Hour: "expires in 59 min", 29*time.Minute + 50*time.Second: "expires in 29 min", 30 * time.Second: "expires in under a minute", 0: "expired, a new one is on its way"} {
		if got := consoleui.Expires(left); got != want {
			t.Errorf("%s: %q", left, got)
		}
	}
}
