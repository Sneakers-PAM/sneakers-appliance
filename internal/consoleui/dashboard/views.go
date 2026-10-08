// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package dashboard is the console in normal operation, information only:
// the status, the addresses and fingerprints, and the warnings. The only
// inputs are Recover access, the network editor when there's no address,
// and cancelling a factory reset that's counting down.
package dashboard

import (
	"fmt"
	"strings"
	"time"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
)

const (
	width = consoleui.Width
	label = 14
)

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
	Platform    sources.PlatformState
	PlatformErr error
	// Recover is a Recover access code that's out.
	Recover *sources.RecoverCode
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

// Info is the header's right side: the slot and the node count.
func Info(d Data) string {
	nodes := d.Platform.Nodes
	if nodes < 1 {
		// The platform counts its nodes once it runs; until then the box
		// itself is the one.
		nodes = 1
	}
	n := "1 node"
	if nodes > 1 {
		n = fmt.Sprintf("%d nodes", nodes)
	}
	return "slot " + d.Slot + "  " + n
}

func status(name string, word string, st tui.Style, detail string) tui.Line {
	return consoleui.StatusLine(name, label, word, st, detail)
}

func health(d Data) tui.Line {
	st := d.Status.Status
	if st == nil {
		return status("Health", "UNKNOWN", tui.Warn, "no status yet")
	}
	ok, all := 0, 0
	for _, h := range st.GetHealth() {
		if h.GetName() == "netd" && sources.IsNotInstalled(d.NetErr) {
			continue
		}
		all++
		if h.GetOk() {
			ok++
		}
	}
	if ok == all {
		return status("Health", "OK", tui.OK, "all services running")
	}
	return status("Health", "DEGRADED", tui.Warn, fmt.Sprintf("%d of %d services running", ok, all))
}

func product(d Data) tui.Line {
	switch {
	case sources.IsNotInstalled(d.PlatformErr):
		return status("Product", "NONE", tui.Dim, "installed from the admin page, Updates")
	case d.PlatformErr != nil:
		return status("Product", "DOWN", tui.Alert, "the platform isn't answering")
	case d.Platform.State == "running":
		return status("Product", "OK", tui.OK, "Sneakers-PAM running")
	}
	return status("Product", strings.ToUpper(d.Platform.State), tui.Warn, "")
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

// Warnings are the dashboard's warning lines, each a "!" in its colour,
// the first sentence in bold and the rest dim: everything Status warns
// about but what has its own line (reduced protection, the clock, the
// self-signed certificate), an upgrade staged or rolled back, the factory
// reset with its countdown, an unhealthy service, accessd not answering,
// and a Recover access code out.
func Warnings(c consoleui.Chrome, d Data, now time.Time) []tui.Line {
	var out []tui.Line
	add := func(st tui.Style, s string) {
		head, rest := s, ""
		if i := strings.Index(s, ". "); i >= 0 {
			head, rest = s[:i+1], s[i+2:]
		}
		for i, l := range tui.WrapStyled(tui.Strong, head, width-2, "") {
			lead := tui.Line{{Text: "  "}}
			if i == 0 {
				lead = tui.Line{{Text: "!", Style: st}, {Text: " "}}
			}
			out = append(out, append(lead, l...))
		}
		if rest != "" {
			out = append(out, tui.WrapStyled(tui.Dim, rest, width-2, "  ")...)
		}
	}
	if err := d.Status.Err; err != nil {
		if d.Status.Status != nil {
			add(tui.Alert, "The appliance services aren't answering; this is the status from "+d.Status.Saved.In(time.Local).Format("15:04 MST")+".")
		} else {
			add(tui.Alert, "The appliance services aren't answering yet; there's no status to show.")
		}
	}
	st := d.Status.Status
	if fr := st.GetFactoryReset(); fr != nil {
		if fr.GetState() == osadminv1.FactoryResetState_FACTORY_RESET_STATE_COUNTDOWN {
			add(tui.Alert, fmt.Sprintf("A factory reset asked for by %s runs in %s unless it's cancelled: press C.", fr.GetStartedBy(), countdown(fr.GetRunsAt().AsTime().Sub(now))))
		} else {
			add(tui.Warn, fmt.Sprintf("A factory reset asked for by %s waits for approval (%d of %d).", fr.GetStartedBy(), len(fr.GetApprovals()), fr.GetRequired()))
		}
	}
	switch {
	case st.GetFailedVersion() != "":
		add(tui.Alert, "The upgrade to "+st.GetFailedVersion()+" was rolled back. The box runs "+st.GetVersion()+" again.")
	case st.GetStagedVersion() != "":
		add(tui.Warn, st.GetStagedVersion()+" is staged. It starts with the next restart.")
	}
	if r := d.Recover; r != nil {
		if r.InUse {
			add(tui.Warn, "A Recover access code is in use from "+r.Source+".")
		} else {
			add(tui.Warn, "A Recover access code is out until "+r.Expires.In(time.Local).Format("15:04")+".")
		}
	}
	for _, w := range st.GetWarnings() {
		switch w.GetKind() {
		case osadminv1.WarningKind_WARNING_KIND_REDUCED_PROTECTION, osadminv1.WarningKind_WARNING_KIND_SELF_SIGNED_TLS,
			osadminv1.WarningKind_WARNING_KIND_FACTORY_RESET, osadminv1.WarningKind_WARNING_KIND_NTP_UNSYNCED:
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

// HasAddress reports whether the box has a management address to show.
func HasAddress(d Data) bool {
	return d.NetErr == nil && len(sources.Hosts(d.Status.Status.GetManagementAddresses())) > 0
}

// Keys are the dashboard's keys: Recover access always, the network
// editor without an address, and cancelling a factory reset counting down.
func Keys(d Data) tui.Line {
	ks := []tui.Line{consoleui.Key("R", "Recover access")}
	if !HasAddress(d) && !sources.IsNotInstalled(d.NetErr) {
		ks = append(ks, consoleui.Key("N", "Network"))
	}
	if fr := d.Status.Status.GetFactoryReset(); fr.GetState() == osadminv1.FactoryResetState_FACTORY_RESET_STATE_COUNTDOWN {
		ks = append(ks, consoleui.Key("C", "Cancel the reset"))
	}
	return consoleui.Keys(ks...)
}

// Page is the status view, in the approved order: the status block, the
// admin page and SSH, the fingerprints, then the warnings.
func Page(c consoleui.Chrome, d Data, now time.Time) tui.Page {
	c.Info = Info(d)
	st := d.Status.Status
	b := []tui.Line{health(d), product(d), c.ProtectionStatus(label), c.ClockLine(label), tui.Text("")}
	urls := sources.URLHosts(st.GetManagementAddresses())
	switch {
	case d.NetErr != nil:
		b = append(b, consoleui.Field("Admin", label, tui.Span{Text: "address not known: " + lowerFirst(d.NetErr.Error()), Style: tui.Warn}))
	case len(urls) == 0:
		b = append(b, consoleui.Field("Admin", label, tui.Span{Text: "no address yet", Style: tui.Warn}))
	default:
		b = append(b, consoleui.Field("Admin", label, tui.Span{Text: "https://" + urls[0] + ":8443", Style: tui.Strong}))
		if h := st.GetHostname(); h != "" {
			b = append(b, consoleui.Field("", label, tui.Span{Text: "https://" + h + ":8443", Style: tui.Strong}))
		}
		b = append(b, consoleui.Field("SSH", label, tui.Span{Text: urls[0] + ":22", Style: tui.Strong}, tui.Span{Text: "  key + TOTP code", Style: tui.Dim}))
	}
	var fps []tui.Line
	for i, l := range consoleui.FingerprintGroups(st.GetTlsFingerprint()) {
		name := ""
		if i == 0 {
			name = ":8443"
		}
		fps = append(fps, tui.Text(fmt.Sprintf("  %-8s%s", name, l)))
	}
	if k, ok := preferred(d.HostKeys); ok {
		for i, l := range consoleui.SSHFingerprintGroups(k.Fingerprint) {
			name := ""
			if i == 0 {
				name = "ssh"
			}
			fps = append(fps, tui.Text(fmt.Sprintf("  %-8s%s", name, l)))
		}
	}
	if len(fps) > 0 {
		b = append(b, tui.Text(""), tui.Styled(tui.Dim, "Fingerprints"))
		b = append(b, fps...)
	}
	if w := Warnings(c, d, now); len(w) > 0 {
		b = append(b, tui.Text(""))
		b = append(b, w...)
	}
	return c.Page(b, Keys(d), "")
}

// preferred is the host key to show: ed25519 when there is one.
func preferred(keys []sources.HostKey) (sources.HostKey, bool) {
	for _, k := range keys {
		if k.Type == "ssh-ed25519" {
			return k, true
		}
	}
	if len(keys) > 0 {
		return keys[0], true
	}
	return sources.HostKey{}, false
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// MaintenancePage is an upgrade in progress, or rolled back with its
// reason.
func MaintenancePage(c consoleui.Chrome, u sources.Upgrade) tui.Page {
	var b []tui.Line
	if u.InProgress {
		b = append(b, tui.Styled(tui.Strong, "Upgrading to "+u.Version+". Leave it powered on."), tui.Text(""))
		b = append(b, tui.Line{{Text: "   "}, {Text: "[..]", Style: tui.Warn}, {Text: "  " + u.Step}}, tui.Text(""))
		b = append(b, tui.Wrap("If "+u.Version+" doesn't come up healthy, the box goes back to "+c.Version+" by itself.", width, "")...)
	}
	if u.Failed != "" {
		b = append(b, tui.Styled(tui.Alert, "The upgrade to "+u.Version+" was rolled back:"))
		b = append(b, tui.WrapStyled(tui.Alert, u.Failed, width, "  ")...)
	}
	return c.BigPage(b)
}

// RecoverPage is Recover access's first screen: the two ways back in.
func RecoverPage(c consoleui.Chrome, errLine string) tui.Page {
	b := []tui.Line{tui.Styled(tui.Strong, "Recover access"), tui.Text(""), tui.Text("Use this only when no admin can sign in."), tui.Text("")}
	b = append(b,
		tui.Line{{Text: "1", Style: tui.Strong}, {Text: "  Let this network reach the admin page again"}},
		tui.Styled(tui.Dim, "   (resets who can connect to the admin page)"),
		tui.Text(""),
		tui.Line{{Text: "2", Style: tui.Strong}, {Text: "  Reset an owner's sign-in with a one-time code"}},
		tui.Text(""),
	)
	b = append(b, tui.Wrap("Both are recorded, and every admin sees a notice the next time they sign in.", width, "")...)
	if errLine != "" {
		b = append(b, tui.Text(""))
		b = append(b, tui.WrapStyled(tui.Alert, errLine, width, "")...)
	}
	return c.Page(b, consoleui.Keys(tui.Line{{Text: "1", Style: tui.Strong}, {Text: " or "}, {Text: "2", Style: tui.Strong}, {Text: "  Choose"}}, consoleui.Key("Enter", "Back")), "")
}

// AllowListPage is who can connect reset: kept with K once the admin page
// opens from this network, put back by itself otherwise.
func AllowListPage(c consoleui.Chrome, revert time.Duration, errLine string) tui.Page {
	b := []tui.Line{tui.Styled(tui.Strong, "Recover access"), tui.Text("")}
	b = append(b, tui.Wrap("Who can connect is reset: the admin page and SSH take connections from the management network again.", width, "")...)
	b = append(b, tui.Text(""))
	b = append(b, tui.Wrap(fmt.Sprintf("Open the admin page from a computer on that network. If it works, press K to keep the change; otherwise it's put back in %s.", countdown(revert)), width, "")...)
	if errLine != "" {
		b = append(b, tui.Text(""))
		b = append(b, tui.WrapStyled(tui.Alert, errLine, width, "")...)
	}
	return c.Page(b, consoleui.Keys(consoleui.Key("K", "Keep it"), consoleui.Key("Enter", "Back")), "")
}

// RecoverCodePage is option 2: the address to open, the certificate to
// check, and the one-time code that opens a new password and
// authenticator for an owner, or a new owner.
func RecoverCodePage(c consoleui.Chrome, r sources.RecoverCode, fp string, now time.Time) tui.Page {
	b := []tui.Line{tui.Styled(tui.Strong, "Reset an owner's sign-in"), tui.Text(""), tui.Text("Open this address in your browser:"), tui.Styled(tui.Strong, "   "+r.URL), tui.Text("")}
	if groups := consoleui.FingerprintGroups(fp); len(groups) > 0 {
		b = append(b, tui.Styled(tui.Dim, "Check that the page's certificate matches:"))
		for _, l := range groups {
			b = append(b, tui.Text("   "+l))
		}
		b = append(b, tui.Text(""))
	}
	code := tui.Line{{Text: "Code  ", Style: tui.Strong}, {Text: strings.ToUpper(r.Code), Style: tui.Accent}}
	if !r.Expires.IsZero() {
		code = append(code, tui.Span{Text: "   " + consoleui.Expires(r.Expires.Sub(now)), Style: tui.Dim})
	}
	b = append(b, code, tui.Text(""))
	if r.InUse {
		b = append(b, tui.Styled(tui.Warn, "In use from "+r.Source+"."))
	} else {
		b = append(b, tui.Wrap(fmt.Sprintf("It works once, with %d tries, and opens only setup step 2: a new password and authenticator for an owner, or a new owner.", max(r.AttemptsLeft, 1)), width, "")...)
	}
	return c.Page(b, consoleui.Keys(consoleui.Key("C", "Cancel the code"), consoleui.Key("Enter", "Back")), "")
}
