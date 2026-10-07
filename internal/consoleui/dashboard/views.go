// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package dashboard is the console in normal operation: the status view,
// the menu of console commands (run through the closed shell's own command
// table), Recover access, the recent messages and the maintenance view.
package dashboard

import (
	"fmt"
	"strings"
	"time"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

const width = consoleui.Width

// Data is one refresh of what the dashboard shows.
type Data struct {
	Status sources.StatusView
	// NetErr is why the addresses aren't known (netd not installed).
	NetErr   error
	Slot     string
	HostKeys []sources.HostKey
	Upgrade  sources.Upgrade
	// UpgradeErr and PlatformErr are their services' answers (NotInstalled
	// until they're in the build).
	UpgradeErr  error
	Platform    string
	PlatformErr error
}

// Slot names the root slot from init's SNEAKERS_ROOT_SOURCE.
func Slot(source string) string {
	switch source {
	case "sneakers-root-a":
		return "A"
	case "sneakers-root-b":
		return "B"
	case "install":
		return "the install medium"
	case "":
		return "unknown"
	}
	return source
}

func secureBoot(c consoleui.Chrome) tui.Span {
	if !c.Known {
		return tui.Span{Text: "unknown (init isn't answering)", Style: tui.Warn}
	}
	switch c.Protection.Reason {
	case keycustody.ReasonSecureBootOff:
		return tui.Span{Text: "off, by choice", Style: tui.Warn}
	case keycustody.ReasonNoSecureBootFirmware:
		return tui.Span{Text: "not in this firmware", Style: tui.Warn}
	}
	return tui.Span{Text: "enforcing, org keys only", Style: tui.OK}
}

func atRest(c consoleui.Chrome) tui.Span {
	switch c.Mode {
	case keycustody.ModeTPM:
		return tui.Span{Text: "TPM", Style: tui.OK}
	case keycustody.ModeKeyfile:
		return tui.Span{Text: "key file", Style: tui.Warn}
	}
	return tui.Span{Text: "unknown"}
}

// pair is two fields on one row.
func pair(l1 string, v1 tui.Span, l2 string, v2 tui.Span) tui.Line {
	left := consoleui.Field(l1, 13, v1)
	pad := 46 - left.Len()
	if pad < 1 {
		pad = 1
	}
	return append(append(left, tui.Span{Text: strings.Repeat(" ", pad)}), consoleui.Field(l2, 10, v2)...)
}

func hosts(addrs []string) []string {
	var out []string
	for _, a := range addrs {
		h := a
		if i := strings.IndexByte(h, '/'); i >= 0 {
			h = h[:i]
		}
		if strings.HasPrefix(strings.ToLower(h), "fe80:") {
			continue
		}
		out = append(out, h)
	}
	return out
}

// countdown is how long until t, as 23h59m or 4m10s.
func countdown(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d >= time.Hour {
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
}

// Warnings are the dashboard's warning lines: everything Status warns
// about but the two shown elsewhere on the screen (reduced protection in
// the banner, the self-signed certificate next to its fingerprint), the
// factory reset with its countdown, unhealthy components, and accessd
// itself not answering.
func Warnings(d Data, now time.Time) []tui.Line {
	var out []tui.Line
	add := func(st tui.Style, s string) {
		for i, l := range tui.WrapStyled(st, s, width-2, "") {
			lead := "  "
			if i == 0 {
				lead = "! "
			}
			out = append(out, append(tui.Line{{Text: lead, Style: st}}, l...))
		}
	}
	if err := d.Status.Err; err != nil {
		if d.Status.Status != nil {
			add(tui.Alert, "The appliance services aren't answering; this is the status from "+d.Status.Saved.UTC().Format("15:04")+" UTC.")
		} else {
			add(tui.Alert, "The appliance services aren't answering yet; there's no status to show.")
		}
	}
	st := d.Status.Status
	if fr := st.GetFactoryReset(); fr != nil {
		if fr.GetState() == osadminv1.FactoryResetState_FACTORY_RESET_STATE_COUNTDOWN {
			add(tui.Alert, fmt.Sprintf("Factory reset requested by %s runs in %s (at %s UTC) unless an admin cancels it: menu, c.", fr.GetStartedBy(), countdown(fr.GetRunsAt().AsTime().Sub(now)), fr.GetRunsAt().AsTime().UTC().Format("15:04")))
		} else {
			add(tui.Warn, fmt.Sprintf("Factory reset requested by %s is waiting for its quorum (%d of %d).", fr.GetStartedBy(), len(fr.GetApprovals()), fr.GetRequired()))
		}
	}
	for _, w := range st.GetWarnings() {
		switch w.GetKind() {
		case osadminv1.WarningKind_WARNING_KIND_REDUCED_PROTECTION, osadminv1.WarningKind_WARNING_KIND_SELF_SIGNED_TLS, osadminv1.WarningKind_WARNING_KIND_FACTORY_RESET:
			continue
		case osadminv1.WarningKind_WARNING_KIND_EXPOSURE:
			add(tui.Alert, w.GetDetail())
		default:
			add(tui.Warn, w.GetDetail())
		}
	}
	for _, h := range st.GetHealth() {
		if h.GetOk() || (h.GetName() == "netd" && sources.IsNotInstalled(d.NetErr)) {
			continue
		}
		add(tui.Warn, h.GetName()+" isn't answering: "+h.GetDetail())
	}
	return out
}

// Page is the status view.
func Page(c consoleui.Chrome, d Data, now time.Time) tui.Page {
	st := d.Status.Status
	var b []tui.Line
	ver := st.GetVersion()
	if ver == "" {
		ver = c.Version
	}
	if ch := st.GetChannel(); ch != "" {
		ver += " (" + ch + " channel)"
	}
	b = append(b, consoleui.Field("Version", 13, tui.Span{Text: ver + ", slot " + d.Slot}))
	b = append(b, pair("Secure Boot", secureBoot(c), "At rest", atRest(c)))
	platform := tui.Span{Text: d.Platform}
	if d.PlatformErr != nil {
		platform = tui.Span{Text: "not installed yet", Style: tui.Warn}
		if !sources.IsNotInstalled(d.PlatformErr) {
			platform = tui.Span{Text: "not answering", Style: tui.Alert}
		}
	}
	upg := tui.Span{Text: "none staged"}
	switch {
	case st.GetFailedVersion() != "":
		upg = tui.Span{Text: "rolled back from " + st.GetFailedVersion(), Style: tui.Alert}
	case st.GetStagedVersion() != "":
		upg = tui.Span{Text: st.GetStagedVersion() + " staged", Style: tui.Bold}
	}
	b = append(b, pair("Platform", platform, "Upgrades", upg))
	switch {
	case d.NetErr != nil:
		b = append(b, consoleui.Field("Management", 13, tui.Span{Text: "no address: " + lowerFirst(d.NetErr.Error()), Style: tui.Warn}))
	case len(st.GetManagementAddresses()) == 0:
		b = append(b, consoleui.Field("Management", 13, tui.Span{Text: "no address yet", Style: tui.Warn}))
	default:
		b = append(b, consoleui.Field("Management", 13, tui.Span{Text: strings.Join(st.GetManagementAddresses(), "  ")}))
	}
	if fp := st.GetTlsFingerprint(); fp != "" {
		url := ":8443"
		if h := hosts(st.GetManagementAddresses()); len(h) > 0 {
			host := h[0]
			if strings.Contains(host, ":") {
				host = "[" + host + "]"
			}
			url = "https://" + host + ":8443/"
		}
		note := ""
		if st.GetTlsSelfSigned() {
			note = "  (self-signed: check the fingerprint)"
		}
		b = append(b, consoleui.Field(":8443", 13, tui.Span{Text: url, Style: tui.Bold}, tui.Span{Text: note}))
		for _, l := range consoleui.FingerprintLines(fp) {
			b = append(b, consoleui.Field("", 13, tui.Span{Text: l}))
		}
	} else {
		b = append(b, consoleui.Field(":8443", 13, tui.Span{Text: "not running yet"}))
	}
	if len(d.HostKeys) == 0 {
		b = append(b, consoleui.Field("SSH host", 13, tui.Span{Text: "no host keys yet (setup's admin step makes them)"}))
	}
	for i, k := range d.HostKeys {
		label := ""
		if i == 0 {
			label = "SSH host"
		}
		b = append(b, consoleui.Field(label, 13, tui.Span{Text: fmt.Sprintf("%-12s %s", k.Type, k.Fingerprint)}))
	}
	if ws := Warnings(d, now); len(ws) > 0 {
		b = append(b, tui.Text(""))
		b = append(b, ws...)
	}
	return c.Page("Status", b, `Enter: menu, or type a console command such as "keys list"`, "> ")
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// MaintenancePage is the upgrade in progress, or rolled back with its
// error.
func MaintenancePage(c consoleui.Chrome, u sources.Upgrade) tui.Page {
	var b []tui.Line
	if u.InProgress {
		b = append(b, tui.Styled(tui.Bold, "Upgrading to "+u.Version))
		b = append(b, consoleui.Field("Step", 8, tui.Span{Text: u.Step}))
		b = append(b, tui.Text(""))
		b = append(b, tui.Wrap("The product is stopped while the box upgrades. Leave it powered on: if the new release doesn't come up, it boots the previous one by itself.", width, "")...)
	}
	if u.Failed != "" {
		b = append(b, tui.Styled(tui.Alert, "The upgrade to "+u.Version+" was rolled back:"))
		b = append(b, tui.WrapStyled(tui.Alert, u.Failed, width, "  ")...)
	}
	return c.Page("Maintenance", b, "", "")
}

// Item is one menu entry.
type Item struct {
	Key, Label string
}

// MenuPage lists the console commands and the console's own screens, in
// two columns.
func MenuPage(c consoleui.Chrome, items []Item, errLine string) tui.Page {
	var b []tui.Line
	half := (len(items) + 1) / 2
	cell := func(i int) string {
		if i >= len(items) {
			return ""
		}
		return fmt.Sprintf("%3s  %s", items[i].Key, items[i].Label)
	}
	for i := 0; i < half; i++ {
		b = append(b, tui.Text(fmt.Sprintf("%-38s %s", cell(i), cell(i+half))))
	}
	if errLine != "" {
		b = append(b, tui.Text(""))
		b = append(b, tui.WrapStyled(tui.Alert, errLine, width, "")...)
	}
	return c.Page("Menu", b, "number: run it   Enter: back to the status", "> ")
}

// ArgsPage asks for what a command takes.
func ArgsPage(c consoleui.Chrome, info shell.Info) tui.Page {
	b := []tui.Line{tui.Styled(tui.Bold, info.Path), tui.Text(info.Short), tui.Text("")}
	usage := info.Use
	for _, f := range info.Flags {
		usage += " [--" + f + " <value>]"
	}
	if info.Stdin {
		b = append(b, tui.Text("Type or paste the public key on one line."))
		return c.Page("Menu", b, "Enter alone: back", "key: ")
	}
	b = append(b, tui.Text("Usage: "+usage), tui.Text("Type its arguments, or press Enter for none."))
	return c.Page("Menu", b, "", info.Path+" ")
}

// CommandPage is a command's transcript: what it printed, the last lines
// first to go when it's long, and the line it waits on as the prompt.
func CommandPage(c consoleui.Chrome, path string, lines []string, prompt string, done bool) tui.Page {
	room := 24 - 4 - 2 - len(c.Banner()) - 2
	if len(c.Banner()) > 0 {
		room--
	}
	if len(lines) > room {
		lines = append([]string{"..."}, lines[len(lines)-room+1:]...)
	}
	b := []tui.Line{tui.Styled(tui.Bold, "> "+path)}
	for _, l := range lines {
		b = append(b, tui.Text(l))
	}
	keys := ""
	if done {
		keys = "Enter: back to the menu"
	}
	return c.Page("Menu", b, keys, prompt)
}

// MessagesPage is the last lines the services wrote while the dashboard
// owned the console.
func MessagesPage(c consoleui.Chrome, lines []string) tui.Page {
	room := 24 - 4 - 2 - len(c.Banner()) - 1
	if len(c.Banner()) > 0 {
		room--
	}
	if len(lines) > room {
		lines = lines[len(lines)-room:]
	}
	b := []tui.Line{tui.Text("The services' and init's latest lines (newest last):")}
	if len(lines) == 0 {
		b = append(b, tui.Text("  none yet"))
	}
	for _, l := range lines {
		b = append(b, tui.Text(l))
	}
	return c.Page("Recent messages", b, "Enter: back", "> ")
}

// RecoverPage is Recover access's first screen: what it does, and whose
// key it adds.
func RecoverPage(c consoleui.Chrome, owners []string, errLine string) tui.Page {
	b := tui.Wrap("When every admin key is lost, this adds a key to an owner, or makes a new owner, through the enrolment window: a code shown here, then a typed yes.", width, "")
	b = append(b, tui.Text(""))
	b = append(b, tui.WrapStyled(tui.Warn, "It's recorded in the OS audit log, every other owner sees a banner on :8443, and the new key can't approve elevations for 24 hours (another owner can lift that).", width, "")...)
	b = append(b, tui.Text(""))
	if len(owners) > 0 {
		b = append(b, tui.Text("Owners: "+strings.Join(owners, ", ")))
	}
	b = append(b, tui.Text("Type an owner's name to add a key to them, or a new name to make a new owner."))
	if errLine != "" {
		b = append(b, tui.Text(""))
		b = append(b, tui.WrapStyled(tui.Alert, errLine, width, "")...)
	}
	return c.Page("Recover access", b, "Enter alone: back", "owner: ")
}

// RecoverDonePage says what Recover access did.
func RecoverDonePage(c consoleui.Chrome, admin string, n int, until time.Time) tui.Page {
	b := []tui.Line{
		tui.Styled(tui.OK, fmt.Sprintf("%d key(s) added to %s with Recover access.", n, admin)),
		tui.Text(""),
	}
	b = append(b, tui.Wrap(fmt.Sprintf("It's in the OS audit log, and every other owner sees a banner on :8443. %s can sign in now, but can't approve elevations until %s UTC.", admin, until.UTC().Format("2006-01-02 15:04")), width, "")...)
	return c.Page("Recover access", b, "Enter: back", "> ")
}
