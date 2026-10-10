// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productspec_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

const withEmail = `format: 2
email:
  label: Password resets and one-time codes
  restart: [sneakers/deployment/sneakers-identity]
box_settings:
  - configmap: sneakers/sneakers-email
    keys:
      - {key: SMTP_HOST, setting: email.host}
      - {key: SMTP_PORT, setting: email.port}
      - {key: SMTP_TLS_MODE, setting: email.tls}
      - {key: SMTP_CA_PEM, setting: email.ca_pem}
box_secrets:
  - secret: sneakers/sneakers-email
    keys:
      - {key: SMTP_PASS, setting: email.password}
  - secret: sneakers/sneakers-kratos
    keys:
      - {key: smtpConnectionURI, setting: email.uri}
      - {key: cipher, generate: password}
`

// A product declares the email settings it reads: the non-secret ones as
// box settings (a ConfigMap the box writes), the password and the URI it's
// in as box secrets, and the workloads that restart when they change.
func TestEmailSettingsParse(t *testing.T) {
	s, err := productspec.Parse([]byte(withEmail))
	if err != nil {
		t.Fatal(err)
	}
	if s.Email == nil || s.Email.Label == "" || len(s.Email.Restart) != 1 {
		t.Fatalf("email = %+v", s.Email)
	}
	if ns, kind, name, ok := s.Email.RestartRef(0); !ok || ns != "sneakers" || kind != "deployment" || name != "sneakers-identity" {
		t.Fatalf("restart = %s %s %s %v", ns, kind, name, ok)
	}
	if len(s.BoxSettings) != 1 || s.BoxSettings[0].Namespace() != "sneakers" || s.BoxSettings[0].ConfigMapName() != "sneakers-email" || len(s.BoxSettings[0].Keys) != 4 {
		t.Fatalf("box settings = %+v", s.BoxSettings)
	}
	if k := s.BoxSecrets[0].Keys[0]; k.Setting != productspec.SettingEmailPassword {
		t.Fatalf("the password key = %+v", k)
	}
	if !s.ReadsEmail() {
		t.Fatal("ReadsEmail = false")
	}
	if (productspec.Spec{}).ReadsEmail() {
		t.Fatal("a product with no email section reads email")
	}
}

// The password, and the URI it's in, never go into a ConfigMap; a setting
// the box doesn't offer, a key that's two kinds at once, and settings with
// no email section to restart their readers are refused.
func TestEmailSettingsAreRefusedWhenTheyBreakARule(t *testing.T) {
	for name, doc := range map[string]string{
		"the password in a ConfigMap": "format: 2\nemail: {}\nbox_settings:\n  - configmap: sneakers/e\n    keys:\n      - {key: SMTP_PASS, setting: email.password}\n",
		"the URI in a ConfigMap":      "format: 2\nemail: {}\nbox_settings:\n  - configmap: sneakers/e\n    keys:\n      - {key: URI, setting: email.uri}\n",
		"an unknown setting":          "format: 2\nemail: {}\nbox_settings:\n  - configmap: sneakers/e\n    keys:\n      - {key: X, setting: email.colour}\n",
		"an unknown secret setting":   "format: 2\nemail: {}\nbox_secrets:\n  - secret: sneakers/e\n    keys:\n      - {key: X, setting: box.fqdn}\n",
		"a setting and a value":       "format: 2\nemail: {}\nbox_secrets:\n  - secret: sneakers/e\n    keys:\n      - {key: X, setting: email.password, value: x}\n",
		"a setting and a generator":   "format: 2\nemail: {}\nbox_secrets:\n  - secret: sneakers/e\n    keys:\n      - {key: X, setting: email.password, generate: password}\n",
		"no email section":            "format: 2\nbox_settings:\n  - configmap: sneakers/e\n    keys:\n      - {key: SMTP_HOST, setting: email.host}\n",
		"no email section, a secret":  "format: 2\nbox_secrets:\n  - secret: sneakers/e\n    keys:\n      - {key: SMTP_PASS, setting: email.password}\n",
		"a bad configmap":             "format: 2\nemail: {}\nbox_settings:\n  - configmap: e\n    keys:\n      - {key: SMTP_HOST, setting: email.host}\n",
		"the appliance's namespace":   "format: 2\nemail: {}\nbox_settings:\n  - configmap: sneakers-appliance/e\n    keys:\n      - {key: SMTP_HOST, setting: email.host}\n",
		"a configmap twice":           "format: 2\nemail: {}\nbox_settings:\n  - configmap: sneakers/e\n    keys:\n      - {key: A, setting: email.host}\n  - configmap: sneakers/e\n    keys:\n      - {key: B, setting: email.port}\n",
		"a key twice":                 "format: 2\nemail: {}\nbox_settings:\n  - configmap: sneakers/e\n    keys:\n      - {key: A, setting: email.host}\n      - {key: A, setting: email.port}\n",
		"no keys":                     "format: 2\nemail: {}\nbox_settings:\n  - configmap: sneakers/e\n",
		"a bad restart":               "format: 2\nemail:\n  restart: [sneakers/pod/x]\n",
	} {
		if _, err := productspec.Parse([]byte(doc)); !codes.Is(err, codes.KitBundleMismatch) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The Sneakers bundle's mail goes out through its identity service, which
// reads every email setting from the box; the password, and the Kratos
// courier URI built with it, only from box secrets.
func TestTheSneakersBundleReadsTheBoxsEmailSettings(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "build", "product", "sneakers", "product.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := productspec.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if !s.ReadsEmail() || len(s.Email.Restart) == 0 {
		t.Fatalf("email = %+v", s.Email)
	}
	cm := map[string]string{}
	for _, bs := range s.BoxSettings {
		for _, k := range bs.Keys {
			cm[bs.ConfigMap+"/"+k.Key] = k.Setting
		}
	}
	for key, setting := range map[string]string{
		"sneakers/sneakers-email/SMTP_HOST":         productspec.SettingEmailHost,
		"sneakers/sneakers-email/SMTP_PORT":         productspec.SettingEmailPort,
		"sneakers/sneakers-email/SMTP_FROM":         productspec.SettingEmailFrom,
		"sneakers/sneakers-email/SMTP_USER":         productspec.SettingEmailUsername,
		"sneakers/sneakers-email/SMTP_TLS_MODE":     productspec.SettingEmailTLS,
		"sneakers/sneakers-email/SMTP_TLS_INSECURE": productspec.SettingEmailSkipVerify,
		"sneakers/sneakers-email/SMTP_CA_PEM":       productspec.SettingEmailCA,
	} {
		if cm[key] != setting {
			t.Errorf("%s = %q, want %s", key, cm[key], setting)
		}
	}
	sec := map[string]string{}
	for _, bs := range s.BoxSecrets {
		for _, k := range bs.Keys {
			sec[bs.Secret+"/"+k.Key] = k.Setting
			if strings.Contains(k.Value, "smtp") {
				t.Errorf("%s/%s carries a fixed SMTP value %q", bs.Secret, k.Key, k.Value)
			}
		}
	}
	if sec["sneakers/sneakers-email/SMTP_PASS"] != productspec.SettingEmailPassword || sec["sneakers/sneakers-kratos/smtpConnectionURI"] != productspec.SettingEmailURI {
		t.Errorf("box secret settings = %v", sec)
	}
}
