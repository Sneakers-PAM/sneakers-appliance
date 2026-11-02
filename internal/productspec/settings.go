// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productspec

import (
	"regexp"
	"strings"
)

// The box settings an admin sets on :8443 for the product, by the names a
// product.yaml reads them under (box_settings and box_secrets keys'
// setting). The box keeps them on the state volume (package boxsettings).
const (
	// SettingEmailHost is the mail relay's host name or address; empty
	// when no relay is set.
	SettingEmailHost = "email.host"
	// SettingEmailPort is the relay's port (587 when unset).
	SettingEmailPort = "email.port"
	// SettingEmailFrom is the address mail is sent from.
	SettingEmailFrom = "email.from"
	// SettingEmailUsername is the relay account; empty for no AUTH.
	SettingEmailUsername = "email.username"
	// SettingEmailTLS is none, starttls or tls (implicit TLS).
	SettingEmailTLS = "email.tls"
	// SettingEmailSkipVerify is "true" when the relay's certificate isn't
	// verified, else "false".
	SettingEmailSkipVerify = "email.skip_verify"
	// SettingEmailCA is the relay's CA, PEM, or empty.
	SettingEmailCA = "email.ca_pem"
	// SettingEmailPassword is the relay account's password. Secret.
	SettingEmailPassword = "email.password"
	// SettingEmailURI is the relay as one smtp:// or smtps:// URI with the
	// account in it, in the form Ory's courier reads. Secret.
	SettingEmailURI = "email.uri"
	// SettingTelemetryEndpoint is the OTLP collector's https address; empty
	// when export is off, whatever endpoint is saved.
	SettingTelemetryEndpoint = "telemetry.endpoint"
	// SettingTelemetrySkipVerify is "true" when the collector's certificate
	// isn't verified, else "false".
	SettingTelemetrySkipVerify = "telemetry.skip_verify"
	// SettingTelemetryLogs is "true" when logs are exported, else "false".
	SettingTelemetryLogs = "telemetry.logs"
	// SettingTelemetryPort is the collector's port while export is on, else
	// empty. The box opens it in its NetworkPolicy; no key reads it.
	SettingTelemetryPort = "telemetry.port"
)

// settings are the settings the box offers, each saying whether it is
// secret: a secret one may only go into a box secret.
var settings = map[string]bool{
	SettingEmailHost: false, SettingEmailPort: false, SettingEmailFrom: false, SettingEmailUsername: false,
	SettingEmailTLS: false, SettingEmailSkipVerify: false, SettingEmailCA: false,
	SettingEmailPassword: true, SettingEmailURI: true,
	SettingTelemetryEndpoint: false, SettingTelemetrySkipVerify: false, SettingTelemetryLogs: false, SettingTelemetryPort: false,
}

// IsSetting reports whether the box offers the setting, and whether it is
// secret.
func IsSetting(name string) (known, secret bool) {
	secret, known = settings[name]
	return known, secret
}

// Email says the product reads the box's email settings, so :8443 offers
// its Email page.
type Email struct {
	// Label says what the product sends mail for.
	Label string `yaml:"label"`
	// Restart are the workloads restarted once a change is in place,
	// <namespace>/<deployment|statefulset|daemonset>/<name>.
	Restart []string `yaml:"restart"`
}

// RestartRef splits Restart[i].
func (e Email) RestartRef(i int) (ns, kind, name string, ok bool) {
	return SplitRestart(e.Restart[i])
}

// SplitRestart splits a <namespace>/<kind>/<name> reference.
func SplitRestart(ref string) (ns, kind, name string, ok bool) {
	m := restartRE.FindStringSubmatch(ref)
	if m == nil {
		return "", "", "", false
	}
	return m[1], m[3], m[4], true
}

// Telemetry says the product reads the box's telemetry settings, so :8443
// offers its Telemetry page.
type Telemetry struct {
	// Label says what the product exports.
	Label string `yaml:"label"`
	// Restart are the workloads that read the settings,
	// <namespace>/<deployment|statefulset|daemonset>/<name>. They restart
	// once a change is in place, in the order of the phases.
	Restart []string `yaml:"restart"`
	// Status is the Service that answers each workload's export state,
	// <namespace>/<service>:<port>, read through the API server's service
	// proxy.
	Status string `yaml:"status"`
	// Egress are the workloads whose NetworkPolicy doesn't reach the
	// collector, <namespace>/<app.kubernetes.io/name>: while export is on
	// the box writes one that opens the collector's port for each.
	Egress []string `yaml:"egress"`
}

// TelemetryStatusPath is what Status answers on.
const TelemetryStatusPath = "/telemetry-status"

// RestartGroup is the workloads of one phase. Phase is empty for a product
// with no phases.
type RestartGroup struct {
	Phase   string
	Restart []string
}

// Groups is Restart in the order of spec's phases, each phase's workloads
// together; with no phases, one group.
func (t Telemetry) Groups(spec Spec) []RestartGroup {
	if len(spec.Phases) == 0 {
		if len(t.Restart) == 0 {
			return nil
		}
		return []RestartGroup{{Restart: t.Restart}}
	}
	var out []RestartGroup
	for i, ph := range spec.Phases {
		var refs []string
		for _, r := range spec.Phases[i].Workloads {
			for j := range t.Restart {
				if _, _, name, ok := t.RestartRef(j); ok && name == r {
					refs = append(refs, t.Restart[j])
				}
			}
		}
		if len(refs) > 0 {
			out = append(out, RestartGroup{Phase: ph.Name, Restart: refs})
		}
	}
	return out
}

// RestartRef splits Restart[i].
func (t Telemetry) RestartRef(i int) (ns, kind, name string, ok bool) {
	return SplitRestart(t.Restart[i])
}

// StatusRef splits Status.
func (t Telemetry) StatusRef() (ns, proxy string, ok bool) {
	ns, proxy, ok = strings.Cut(t.Status, "/")
	if !ok || !dnsRE.MatchString(ns) || !telemetryProxyRE.MatchString(proxy) {
		return "", "", false
	}
	return ns, proxy, true
}

var telemetryProxyRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?:[0-9]{1,5}$`)

// BoxSetting is one ConfigMap the box writes from its settings.
type BoxSetting struct {
	// ConfigMap is <namespace>/<name>.
	ConfigMap string       `yaml:"configmap"`
	Keys      []SettingKey `yaml:"keys"`
}

// SettingKey is one key of a box settings ConfigMap.
type SettingKey struct {
	Key     string `yaml:"key"`
	Setting string `yaml:"setting"`
}

// Namespace is the ConfigMap's namespace.
func (b BoxSetting) Namespace() string { ns, _, _ := strings.Cut(b.ConfigMap, "/"); return ns }

// ConfigMapName is the ConfigMap's name.
func (b BoxSetting) ConfigMapName() string { _, n, _ := strings.Cut(b.ConfigMap, "/"); return n }

// ReadsEmail reports whether the product reads the box's email settings.
func (s Spec) ReadsEmail() bool { return s.Email != nil }

// ReadsTelemetry reports whether the product reads the box's telemetry
// settings.
func (s Spec) ReadsTelemetry() bool { return s.Telemetry != nil }

// TelemetryMinBase is the first base release that reads a product.yaml's
// telemetry section and its settings. An older base refuses the whole
// product.yaml, so a bundle that has one is sealed for this base or newer.
const TelemetryMinBase = "0.1.0-rc.7"

// BaseFloor is the oldest base release that can apply the product, and
// why, from the sections it uses; "" when any base that reads format 2
// can.
func (s Spec) BaseFloor() (version, why string) {
	if s.ReadsTelemetry() {
		return TelemetryMinBase, "it reads the box's telemetry settings"
	}
	return "", ""
}

// settingSection says why the product can't read the setting: the section
// of product.yaml it belongs to is missing.
func (s Spec) settingSection(name string) string {
	switch {
	case strings.HasPrefix(name, "telemetry."):
		if s.Telemetry == nil {
			return "a telemetry setting, and product.yaml has no telemetry section"
		}
	case s.Email == nil:
		return "an email setting, and product.yaml has no email section"
	}
	return ""
}

func (s Spec) checkSettings() error {
	if e := s.Email; e != nil {
		for j := range e.Restart {
			if _, _, _, ok := e.RestartRef(j); !ok {
				return bad("email.restart: %q isn't <namespace>/<deployment|statefulset|daemonset>/<name>", e.Restart[j])
			}
		}
	}
	if t := s.Telemetry; t != nil {
		for j := range t.Restart {
			_, _, name, ok := t.RestartRef(j)
			if !ok {
				return bad("telemetry.restart: %q isn't <namespace>/<deployment|statefulset|daemonset>/<name>", t.Restart[j])
			}
			if _, phased := s.PhaseOf(name); len(s.Phases) > 0 && !phased {
				return bad("telemetry.restart: no phase names %s", name)
			}
		}
		if _, _, ok := t.StatusRef(); t.Status != "" && !ok {
			return bad("telemetry.status: %q isn't <namespace>/<service>:<port>", t.Status)
		}
		for _, e := range t.Egress {
			ns, name, ok := strings.Cut(e, "/")
			if !ok || !dnsRE.MatchString(ns) || !dnsRE.MatchString(name) {
				return bad("telemetry.egress: %q isn't <namespace>/<name>", e)
			}
		}
	}
	maps := map[string]bool{}
	for i, b := range s.BoxSettings {
		ns, name, ok := strings.Cut(b.ConfigMap, "/")
		if !ok || !dnsRE.MatchString(ns) || !secretRE.MatchString(name) {
			return bad("box_settings[%d]: the configmap %q isn't <namespace>/<name>", i, b.ConfigMap)
		}
		if ns == Namespace {
			return bad("box_settings[%d]: %s is the appliance's own namespace", i, ns)
		}
		if maps[b.ConfigMap] {
			return bad("box_settings[%d]: %s is declared twice", i, b.ConfigMap)
		}
		maps[b.ConfigMap] = true
		if len(b.Keys) == 0 {
			return bad("box_settings[%d]: %s has no keys", i, b.ConfigMap)
		}
		keys := map[string]bool{}
		for j, k := range b.Keys {
			if !keyRE.MatchString(k.Key) || keys[k.Key] {
				return bad("box_settings[%d].keys[%d]: %q isn't a ConfigMap data key, or is declared twice", i, j, k.Key)
			}
			keys[k.Key] = true
			known, secret := IsSetting(k.Setting)
			switch {
			case !known:
				return bad("box_settings[%d].keys[%d]: the box offers no setting %q", i, j, k.Setting)
			case secret:
				return bad("box_settings[%d].keys[%d]: %s is secret; it goes into a box secret, never a ConfigMap", i, j, k.Setting)
			case s.settingSection(k.Setting) != "":
				return bad("box_settings[%d].keys[%d]: %s is %s", i, j, k.Setting, s.settingSection(k.Setting))
			}
		}
	}
	for i, b := range s.BoxSecrets {
		for j, k := range b.Keys {
			if k.Setting == "" {
				continue
			}
			if known, _ := IsSetting(k.Setting); !known {
				return bad("box_secrets[%d].keys[%d]: the box offers no setting %q", i, j, k.Setting)
			}
			if why := s.settingSection(k.Setting); why != "" {
				return bad("box_secrets[%d].keys[%d]: %s is %s", i, j, k.Setting, why)
			}
		}
	}
	return nil
}
