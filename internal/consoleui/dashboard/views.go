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
	Platform sources.PlatformState
	// PlatformErr is the platform's answer (NotInstalled until it's in the
	// build).
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

// base is the base release running, its slot, and what's staged or kept
// to go back to.
func base(d Data) tui.Line {
	st := d.Status.Status
	if st == nil {
		return status("Base", "UNKNOWN", tui.Warn, "no status yet")
	}
	v := st.GetRunningVersion()
	if v == "" {
		v = st.GetVersion()
	}
	detail := v + " in slot " + d.Slot
	switch {
	case st.GetStagedVersion() != "":
		detail += "; " + st.GetStagedVersion() + " staged"
	case st.GetPreviousVersion() != "":
		detail += "; " + st.GetPreviousVersion() + " to go back"
	}
	return status("Base", "OK", tui.OK, detail)
}

// product is the product bundle: from platformd once it's in the build,
// until then from the product's slots in Status.
func product(d Data, now time.Time) tui.Line {
	switch {
	case sources.IsNotInstalled(d.PlatformErr):
		return productSlots(d.Status.Status, now)
	case d.PlatformErr != nil:
		return status("Product", "DOWN", tui.Alert, "the platform isn't answering")
	case d.Platform.State == "running":
		return status("Product", "OK", tui.OK, "Sneakers-PAM running")
	}
	return status("Product", strings.ToUpper(d.Platform.State), tui.Warn, "")
}

// productSlots is the Product line from Status's product slots: NONE
// before the first install, FAILED for a day after a product apply or
// revert failed once it had touched the running product, else whether
// the installed version runs, with what's staged or kept to go back to. A
// bundle refused or rejected before that (while it was verified or
// staged) leaves the line as the product runs.
func productSlots(st *osadminv1.GetStatusResponse, now time.Time) tui.Line {
	if st == nil {
		return status("Product", "UNKNOWN", tui.Warn, "no status yet")
	}
	p := st.GetProduct()
	if u := st.GetUpgradeProgress(); u.GetTarget() == osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT && u.GetFailed() && touchedProduct(u) && now.Sub(u.GetUpdatedAt().AsTime()) < failedStepShown {
		return status("Product", "FAILED", tui.Alert, "the update to "+u.GetVersion()+" failed")
	}
	v := p.GetInstalledVersion()
	if v == "" {
		if s := p.GetStagedVersion(); s != "" {
			return status("Product", "NONE", tui.Dim, s+" staged; install it from Updates")
		}
		return status("Product", "NONE", tui.Dim, "installed from the admin page, Updates")
	}
	if !p.GetRunning() {
		return status("Product", "STOPPED", tui.Alert, v+" isn't running")
	}
	detail := v + " running"
	switch {
	case p.GetStagedVersion() != "":
		detail += "; " + p.GetStagedVersion() + " staged"
	case p.GetPreviousVersion() != "":
		detail += "; " + p.GetPreviousVersion() + " to go back"
	}
	return status("Product", "OK", tui.OK, detail)
}

// touchedProduct is whether a failed product action got to the running
// product: an apply or a revert whose failed step is the switch or after
// it. A stage, or a step before the switch, leaves it as it was.
func touchedProduct(p *osadminv1.UpgradeProgress) bool {
	if p.GetAction() != "apply" && p.GetAction() != "revert" {
		return false
	}
	switched := false
	for _, s := range p.GetSteps() {
		if s.GetId() == "switch" {
			switched = true
		}
		if s.GetState() == osadminv1.UpgradeStepState_UPGRADE_STEP_STATE_FAILED {
			return switched
		}
	}
	return false
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
// and a Recover access code out. A critical warning (a volume 90% full)
// shows in the alert colour.
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
			add(tui.Alert, "The appliance services aren't answering; this is the status from "+d.Status.Saved.In(now.Location()).Format("15:04 MST")+".")
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
	switch p := st.GetUpgradeProgress(); {
	case p.GetFailed() && now.Sub(p.GetUpdatedAt().AsTime()) < failedStepShown:
		s := failedStep(p)
		add(tui.Alert, "The update to "+p.GetVersion()+" failed. "+s.GetLabel()+": "+s.GetDetail())
	case st.GetRevertedVersion() != "":
		add(tui.Normal, "Reverted from "+st.GetRevertedVersion()+" by "+st.GetRevertedBy()+" at "+st.GetRevertedAt().AsTime().In(now.Location()).Format("15:04 MST")+". The box runs "+st.GetVersion()+" again.")
	case st.GetFailedVersion() != "":
		add(tui.Alert, "The upgrade to "+st.GetFailedVersion()+" was rolled back. The box runs "+st.GetVersion()+" again.")
	case st.GetStagedVersion() != "":
		add(tui.Warn, st.GetStagedVersion()+" is staged. It starts with the next restart.")
	}
	if r := d.Recover; r != nil {
		if r.InUse {
			add(tui.Warn, "A Recover access code is in use from "+r.Source+".")
		} else {
			add(tui.Warn, "A Recover access code is out until "+r.Expires.In(now.Location()).Format("15:04")+".")
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
			if w.GetCritical() {
				add(tui.Alert, w.GetDetail())
				continue
			}
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
	b := []tui.Line{health(d), base(d), product(d, now), c.ProtectionStatus(label), c.ClockLine(label), tui.Text("")}
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
		b = append(b, consoleui.Field("SSH", label, tui.Span{Text: urls[0] + ":22", Style: tui.Strong}),
			consoleui.Field("", label, tui.Span{Text: "key from :8443 Access, then TOTP", Style: tui.Dim}))
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

// Screen is the status view's page: the maintenance screen while an update
// step is active, otherwise the status screen, which warns about a step
// that failed (a reboot that never came, say).
func Screen(c consoleui.Chrome, d Data, now time.Time) tui.Page {
	// A Base Web switch takes seconds and leaves the box and the product
	// alone: the status screen stays.
	if p := d.Status.Status.GetUpgradeProgress(); p.GetInProgress() && p.GetTarget() != osadminv1.UpdateTarget_UPDATE_TARGET_BASE_WEB {
		return MaintenancePage(c, p)
	}
	return Page(c, d, now)
}

// failedStepShown is how long the status view warns about a failed
// update step; Updates on :8443 keeps it until the next update.
const failedStepShown = 24 * time.Hour

// failedStep is the step that failed, or an empty one.
func failedStep(p *osadminv1.UpgradeProgress) *osadminv1.UpgradeStep {
	for _, s := range p.GetSteps() {
		if s.GetState() == osadminv1.UpgradeStepState_UPGRADE_STEP_STATE_FAILED {
			return s
		}
	}
	return &osadminv1.UpgradeStep{}
}

// stepMarks are each step state's mark, in its colour.
var stepMarks = map[osadminv1.UpgradeStepState]tui.Span{
	osadminv1.UpgradeStepState_UPGRADE_STEP_STATE_PENDING: {Text: "[  ]", Style: tui.Dim},
	osadminv1.UpgradeStepState_UPGRADE_STEP_STATE_ACTIVE:  {Text: "[..]", Style: tui.Warn},
	osadminv1.UpgradeStepState_UPGRADE_STEP_STATE_DONE:    {Text: "[ok]", Style: tui.OK},
	osadminv1.UpgradeStepState_UPGRADE_STEP_STATE_FAILED:  {Text: "[!!]", Style: tui.Alert},
}

// barWidth is the progress bar's cells between its brackets.
const barWidth = 20

// progressBar is done of total as a bar, the percentage and the sizes.
func progressBar(done, total int64) tui.Line {
	done = min(max(done, 0), total)
	filled := int(done * barWidth / total)
	pct := done * 100 / total
	return tui.Line{
		{Text: "        ["},
		{Text: strings.Repeat("#", filled), Style: tui.Warn},
		{Text: strings.Repeat("-", barWidth-filled), Style: tui.Dim},
		{Text: fmt.Sprintf("]  %d%%  ", pct)},
		{Text: fmt.Sprintf("%s of %s", size(done), size(total)), Style: tui.Dim},
	}
}

// size is a byte count in MB or GB, one decimal.
func size(n int64) string {
	if n >= 1<<30 {
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	}
	return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
}

// MaintenancePage is an update in progress: what it does, each step with
// the current one marked, its progress where it has one, and what the box
// does if the new release doesn't come up.
func MaintenancePage(c consoleui.Chrome, p *osadminv1.UpgradeProgress) tui.Page {
	product := p.GetTarget() == osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT
	head := "Updating to " + p.GetVersion() + ". Leave it powered on."
	switch {
	case product && p.GetAction() == "apply":
		head = "Installing the product " + p.GetVersion() + ". The box keeps running."
	case product && p.GetAction() == "revert":
		head = "Going back to the product " + p.GetVersion() + ". The box keeps running."
	case p.GetAction() == "revert":
		head = "Going back to " + p.GetVersion() + ". Leave it powered on."
	case p.GetAction() == "stage":
		head = "Staging " + p.GetVersion() + ". The box keeps running."
	}
	b := []tui.Line{tui.Styled(tui.Strong, head), tui.Text("")}
	for _, s := range p.GetSteps() {
		st := s.GetState()
		text := tui.Span{Text: "  " + s.GetLabel()}
		if st == osadminv1.UpgradeStepState_UPGRADE_STEP_STATE_ACTIVE {
			text.Style = tui.Strong
		}
		if st == osadminv1.UpgradeStepState_UPGRADE_STEP_STATE_PENDING {
			text.Style = tui.Dim
		}
		b = append(b, tui.Line{{Text: "  "}, stepMarks[st], text})
		if st != osadminv1.UpgradeStepState_UPGRADE_STEP_STATE_ACTIVE {
			continue
		}
		if s.GetTotalBytes() > 0 {
			b = append(b, progressBar(s.GetDoneBytes(), s.GetTotalBytes()))
		}
		if d := s.GetDetail(); d != "" {
			b = append(b, tui.WrapStyled(tui.Dim, d, width, "        ")...)
		}
	}
	if !product && p.GetAction() == "apply" && p.GetVersion() != c.Version {
		b = append(b, tui.Text(""))
		b = append(b, tui.Wrap("If "+p.GetVersion()+" doesn't come up healthy, the box goes back to "+c.Version+" by itself.", width, "")...)
	}
	return c.Page(b, consoleui.Keys(consoleui.Key("R", "Recover access")), "")
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
		tui.Line{{Text: "0", Style: tui.Strong}, {Text: "  Back"}},
		tui.Text(""),
	)
	b = append(b, tui.Wrap("Both are recorded, and every admin sees a notice the next time they sign in.", width, "")...)
	if errLine != "" {
		b = append(b, tui.Text(""))
		b = append(b, tui.WrapStyled(tui.Alert, errLine, width, "")...)
	}
	return c.Page(b, consoleui.Keys(tui.Line{{Text: "1", Style: tui.Strong}, {Text: ", "}, {Text: "2", Style: tui.Strong}, {Text: " or "}, {Text: "0", Style: tui.Strong}, {Text: "  Choose"}}, consoleui.Key("Enter", "Back")), "")
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
