// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productspec

import "strings"

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
)

// settings are the settings the box offers, each saying whether it is
// secret: a secret one may only go into a box secret.
var settings = map[string]bool{
	SettingEmailHost: false, SettingEmailPort: false, SettingEmailFrom: false, SettingEmailUsername: false,
	SettingEmailTLS: false, SettingEmailSkipVerify: false, SettingEmailCA: false,
	SettingEmailPassword: true, SettingEmailURI: true,
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
	m := restartRE.FindStringSubmatch(e.Restart[i])
	if m == nil {
		return "", "", "", false
	}
	return m[1], m[3], m[4], true
}

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

func (s Spec) checkSettings() error {
	if e := s.Email; e != nil {
		for j := range e.Restart {
			if _, _, _, ok := e.RestartRef(j); !ok {
				return bad("email.restart: %q isn't <namespace>/<deployment|statefulset|daemonset>/<name>", e.Restart[j])
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
			case s.Email == nil:
				return bad("box_settings[%d].keys[%d]: %s is an email setting, and product.yaml has no email section", i, j, k.Setting)
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
			if s.Email == nil {
				return bad("box_secrets[%d].keys[%d]: %s is an email setting, and product.yaml has no email section", i, j, k.Setting)
			}
		}
	}
	return nil
}
