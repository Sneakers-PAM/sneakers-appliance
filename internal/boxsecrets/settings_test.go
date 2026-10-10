// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package boxsecrets_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxsecrets"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxsettings"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

const emailSpec = `format: 2
email:
  restart: [sneakers/deployment/sneakers-identity]
box_settings:
  - configmap: sneakers/sneakers-email
    keys:
      - {key: SMTP_HOST, setting: email.host}
      - {key: SMTP_PORT, setting: email.port}
      - {key: SMTP_FROM, setting: email.from}
      - {key: SMTP_USER, setting: email.username}
      - {key: SMTP_TLS_MODE, setting: email.tls}
      - {key: SMTP_TLS_INSECURE, setting: email.skip_verify}
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

type object struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name        string            `yaml:"name"`
		Namespace   string            `yaml:"namespace"`
		Annotations map[string]string `yaml:"annotations"`
	} `yaml:"metadata"`
	Data       map[string]string `yaml:"data"`
	StringData map[string]string `yaml:"stringData"`
}

func objects(t *testing.T, manifests string) []object {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(manifests, productspec.BoxSecretsStack, productspec.BoxSecretsStack+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var out []object
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	for {
		var o object
		if err := dec.Decode(&o); err != nil {
			break
		}
		out = append(out, o)
	}
	return out
}

func find(objs []object, kind, name string) (object, bool) {
	for _, o := range objs {
		if o.Kind == kind && o.Metadata.Namespace+"/"+o.Metadata.Name == name {
			return o, true
		}
	}
	return object{}, false
}

type settingsFrom struct{ e boxsettings.Email }

func (s settingsFrom) Values() (map[string]string, error) { return s.e.Values(), nil }

// The box writes its email settings into the stack: the non-secret ones
// as the ConfigMap the product loads, the password and the URI only into
// Secrets. Every key has its value, in every TLS mode, and no
// placeholder or example relay is left.
func TestTheEmailSettingsGoIntoTheStack(t *testing.T) {
	for _, mode := range []string{boxsettings.TLSNone, boxsettings.TLSStartTLS, boxsettings.TLSImplicit} {
		t.Run(mode, func(t *testing.T) {
			e := boxsettings.Email{Host: "relay.example.org", Port: 587, From: "no-reply@sneakers.example.org", Username: "mailer", Password: "s3cret-relay-pass", TLS: mode, Verify: mode != boxsettings.TLSNone}
			st := boxsecrets.Store{Dir: t.TempDir(), Manifests: t.TempDir(), Settings: settingsFrom{e}}
			if err := st.Ensure(slot(t, emailSpec)); err != nil {
				t.Fatal(err)
			}
			objs := objects(t, st.Manifests)
			cm, ok := find(objs, "ConfigMap", "sneakers/sneakers-email")
			if !ok {
				t.Fatal("no sneakers-email ConfigMap")
			}
			want := map[string]string{"SMTP_HOST": "relay.example.org", "SMTP_PORT": "587", "SMTP_FROM": e.From, "SMTP_USER": "mailer",
				"SMTP_TLS_MODE": mode, "SMTP_TLS_INSECURE": map[bool]string{true: "false", false: "true"}[e.Verify], "SMTP_CA_PEM": ""}
			for k, v := range want {
				if got, ok := cm.Data[k]; !ok || got != v {
					t.Errorf("ConfigMap %s = %q, want %q", k, got, v)
				}
			}
			for _, o := range objs {
				all := ""
				for k, v := range o.Data {
					all += k + "=" + v + "\n"
				}
				if o.Kind == "ConfigMap" && (strings.Contains(all, e.Password) || strings.Contains(all, "SMTP_PASS") || strings.Contains(all, "smtp://") || strings.Contains(all, "smtps://")) {
					t.Errorf("the password or the URI is in the ConfigMap %s:\n%s", o.Metadata.Name, all)
				}
				for _, v := range o.Data {
					if strings.Contains(v, ".invalid") || strings.Contains(v, "smtp.example.org") {
						t.Errorf("a placeholder is left in %s: %q", o.Metadata.Name, v)
					}
				}
				for _, v := range o.StringData {
					if strings.Contains(v, ".invalid") || strings.Contains(v, "smtp.example.org") {
						t.Errorf("a placeholder is left in %s: %q", o.Metadata.Name, v)
					}
				}
			}
			sec, _ := find(objs, "Secret", "sneakers/sneakers-email")
			if sec.StringData["SMTP_PASS"] != e.Password {
				t.Errorf("SMTP_PASS = %q", sec.StringData["SMTP_PASS"])
			}
			k, _ := find(objs, "Secret", "sneakers/sneakers-kratos")
			if k.StringData["smtpConnectionURI"] != e.URI() || k.StringData["cipher"] == "" {
				t.Errorf("the kratos Secret = %v", k.StringData)
			}
		})
	}
}

// Every object carries the stack's revision, which changes with the
// settings, so the box can tell when k0s has applied a change.
func TestTheStackCarriesItsRevision(t *testing.T) {
	e := boxsettings.Email{Host: "relay.example.org", Port: 587, From: "no-reply@sneakers.example.org", TLS: boxsettings.TLSStartTLS, Verify: true}
	dir, man := t.TempDir(), t.TempDir()
	sl := slot(t, emailSpec)
	rev := func(e boxsettings.Email) string {
		st := boxsecrets.Store{Dir: dir, Manifests: man, Settings: settingsFrom{e}}
		if err := st.Ensure(sl); err != nil {
			t.Fatal(err)
		}
		objs := objects(t, man)
		r := objs[0].Metadata.Annotations[boxsecrets.RevisionAnnotation]
		for _, o := range objs {
			if o.Metadata.Annotations[boxsecrets.RevisionAnnotation] != r || r == "" {
				t.Fatalf("%s %s has revision %q, want %q", o.Kind, o.Metadata.Name, o.Metadata.Annotations[boxsecrets.RevisionAnnotation], r)
			}
		}
		got, err := boxsecrets.StackRevision(filepath.Join(man, productspec.BoxSecretsStack, productspec.BoxSecretsStack+".yaml"))
		if err != nil || got != r {
			t.Fatalf("StackRevision = %q, %v; want %q", got, err, r)
		}
		return r
	}
	a := rev(e)
	if b := rev(e); b != a {
		t.Fatalf("the same settings changed the revision: %s, %s", a, b)
	}
	e.Port = 465
	if c := rev(e); c == a {
		t.Fatal("a change kept the revision")
	}
}

// With no settings source the defaults go in: no relay.
func TestWithoutSettingsTheDefaultsGoIn(t *testing.T) {
	st := boxsecrets.Store{Dir: t.TempDir(), Manifests: t.TempDir()}
	if err := st.Ensure(slot(t, emailSpec)); err != nil {
		t.Fatal(err)
	}
	cm, ok := find(objects(t, st.Manifests), "ConfigMap", "sneakers/sneakers-email")
	if !ok || cm.Data["SMTP_HOST"] != "" || cm.Data["SMTP_PORT"] != "587" {
		t.Fatalf("ConfigMap = %+v", cm.Data)
	}
}
