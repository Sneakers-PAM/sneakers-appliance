// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxsecrets"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxsettings"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

const emailYAML = `format: 2
email:
  label: Password resets
  restart: [sneakers/deployment/sneakers-identity]
box_settings:
  - configmap: sneakers/sneakers-email
    keys:
      - {key: SMTP_HOST, setting: email.host}
      - {key: SMTP_PORT, setting: email.port}
      - {key: SMTP_TLS_MODE, setting: email.tls}
box_secrets:
  - secret: sneakers/sneakers-email
    keys:
      - {key: SMTP_PASS, setting: email.password}
`

const relayPassword = "not-a-real-relay-password"

// emailBox is a box with the product installed that reads email settings,
// its box secrets stack written for real, and fakes for the test email
// and the workloads.
type emailBox struct {
	*box
	alice    *browser
	settings *boxsettings.Store
	man      string
	mu       sync.Mutex
	sent     []boxsettings.Email
	sendErr  error
	restarts chan string
	applied  int
}

func (e *emailBox) Applied(context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.applied++
	return nil
}

func (e *emailBox) Restart(_ context.Context, ns, kind, name string) error {
	e.restarts <- ns + "/" + kind + "/" + name
	return nil
}

func newEmailBox(t *testing.T, spec string) *emailBox {
	t.Helper()
	e := &emailBox{restarts: make(chan string, 8)}
	b := newBox(t, true, func(b *box, o *osadmin.Options) {
		e.settings = &boxsettings.Store{Dir: filepath.Join(b.state, "platform")}
		e.man = filepath.Join(b.state, "k0s-manifests")
		o.Email = e.settings
		o.BoxSecrets = &boxsecrets.Store{Dir: filepath.Join(b.state, "platform"), Manifests: e.man, Settings: e.settings}
		o.EmailWorkloads = e
		o.SendEmail = func(_ context.Context, m boxsettings.Email, to string) (string, error) {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.sent = append(e.sent, m)
			if e.sendErr != nil {
				return "", e.sendErr
			}
			return "250 queued as " + to, nil
		}
	})
	e.box = b
	e.alice = b.browser()
	e.alice.signIn("alice")
	e.alice.installProduct(t, "0.2.0")
	if spec != "" {
		if err := os.WriteFile(filepath.Join(b.state, "product", "current", productspec.File), []byte(spec), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func (e *emailBox) client(br *browser) osadminv1connect.EmailServiceClient {
	return osadminv1connect.NewEmailServiceClient(br.hc, e.ts.URL)
}

func relaySettings() *osadminv1.EmailSettings {
	return &osadminv1.EmailSettings{Host: "relay.example.org", Port: 587, From: "no-reply@sneakers.example.org", Username: "mailer", Tls: osadminv1.EmailTls_EMAIL_TLS_STARTTLS, Verify: true}
}

func (e *emailBox) stack() string {
	b, err := os.ReadFile(filepath.Join(e.man, productspec.BoxSecretsStack, productspec.BoxSecretsStack+".yaml"))
	if err != nil {
		e.t.Fatal(err)
	}
	return string(b)
}

func (e *emailBox) restarted(t *testing.T) string {
	t.Helper()
	select {
	case r := <-e.restarts:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("no workload restarted")
	}
	return ""
}

// Saving the relay needs a step-up, applies the product again under the
// maintenance gate (k0s restarts), writes the settings into the stack and
// then restarts the workloads that read them. The password is never sent
// back, never in the audit entry and never in a ConfigMap.
func TestSavingTheEmailSettingsAppliesTheProductAgain(t *testing.T) {
	e := newEmailBox(t, emailYAML)
	ctx := context.Background()
	ec := e.client(e.alice)
	g, err := ec.GetEmail(ctx, connect.NewRequest(&osadminv1.GetEmailRequest{}))
	if err != nil || g.Msg.GetState() != "not set" || g.Msg.GetLabel() != "Password resets" || g.Msg.GetSettings().GetPort() != 587 ||
		g.Msg.GetSettings().GetTls() != osadminv1.EmailTls_EMAIL_TLS_STARTTLS || !g.Msg.GetSettings().GetVerify() || g.Msg.GetPasswordSet() {
		t.Fatalf("%v %v", g, err)
	}
	e.clk.Advance(6 * time.Minute)
	pass := relayPassword
	req := &osadminv1.SetEmailRequest{Settings: relaySettings(), Password: &pass}
	_, err = ec.SetEmail(ctx, connect.NewRequest(req))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_STEPUP_REQUIRED")
	e.alice.stepUp("alice")
	before := len(e.services.log())
	if _, err := ec.SetEmail(ctx, connect.NewRequest(req)); err != nil {
		t.Fatal(err)
	}
	if got := e.services.log()[before:]; !slices.Equal(got, []string{"stop k0s", "start k0s"}) {
		t.Fatalf("services %v", got)
	}
	if r := e.restarted(t); r != "sneakers/deployment/sneakers-identity" {
		t.Fatalf("restarted %s", r)
	}
	stack := e.stack()
	for _, want := range []string{`SMTP_HOST: "relay.example.org"`, `SMTP_PORT: "587"`, `SMTP_TLS_MODE: "starttls"`, `SMTP_PASS: "` + relayPassword + `"`} {
		if !strings.Contains(stack, want) {
			t.Errorf("the stack lacks %s:\n%s", want, stack)
		}
	}
	for _, doc := range strings.Split(stack, "---\n") {
		if strings.Contains(doc, "kind: ConfigMap") && strings.Contains(doc, relayPassword) {
			t.Fatalf("the password is in a ConfigMap:\n%s", doc)
		}
	}
	g, _ = ec.GetEmail(ctx, connect.NewRequest(&osadminv1.GetEmailRequest{}))
	if g.Msg.GetState() != "set" || !g.Msg.GetPasswordSet() || g.Msg.GetSettings().GetHost() != "relay.example.org" || !g.Msg.GetEncrypted() {
		t.Fatalf("%v", g.Msg)
	}
	if strings.Contains(g.Msg.String(), relayPassword) {
		t.Fatal("GetEmail sends the password back")
	}
	a := lastEntry(t, e.log, "product.email.set")
	if a.Outcome != "ok" || a.Detail["host"] != "relay.example.org" || a.Detail["password"] != "set" || a.Detail["tls"] != "starttls" {
		t.Fatalf("audit %+v", a)
	}
	for k, v := range a.Detail {
		if strings.Contains(v, relayPassword) || strings.Contains(k, relayPassword) {
			t.Fatalf("the audit entry carries the password: %+v", a)
		}
	}
	_ = filepath.WalkDir(filepath.Join(e.state, "os-audit"), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if b, _ := os.ReadFile(p); strings.Contains(string(b), relayPassword) {
				t.Errorf("the OS audit log %s carries the password", p)
			}
		}
		return nil
	})

	// Saving again without a password keeps the saved one; TLS off is
	// saved, and reported as unencrypted.
	s := relaySettings()
	s.Tls, s.Verify = osadminv1.EmailTls_EMAIL_TLS_NONE, false
	if _, err := ec.SetEmail(ctx, connect.NewRequest(&osadminv1.SetEmailRequest{Settings: s})); err != nil {
		t.Fatal(err)
	}
	e.restarted(t)
	saved, _ := e.settings.Email()
	if saved.Password != relayPassword || saved.TLS != boxsettings.TLSNone {
		t.Fatalf("saved %+v", saved)
	}
	g, _ = ec.GetEmail(ctx, connect.NewRequest(&osadminv1.GetEmailRequest{}))
	if g.Msg.GetEncrypted() {
		t.Fatal("TLS off is reported as encrypted")
	}
	if a := lastEntry(t, e.log, "product.email.set"); a.Detail["password"] != "kept" || a.Detail["tls"] != "none" || a.Detail["verify"] != "off" {
		t.Fatalf("audit %+v", a)
	}
	// An empty password clears it.
	empty := ""
	if _, err := ec.SetEmail(ctx, connect.NewRequest(&osadminv1.SetEmailRequest{Settings: relaySettings(), Password: &empty})); err != nil {
		t.Fatal(err)
	}
	e.restarted(t)
	if saved, _ := e.settings.Email(); saved.Password != "" {
		t.Fatal("the password wasn't cleared")
	}
}

func TestBadEmailSettingsAreRefusedBeforeAnything(t *testing.T) {
	e := newEmailBox(t, emailYAML)
	ctx := context.Background()
	e.alice.stepUp("alice")
	ec := e.client(e.alice)
	before := len(e.services.log())
	s := relaySettings()
	s.From = "not an address"
	_, err := ec.SetEmail(ctx, connect.NewRequest(&osadminv1.SetEmailRequest{Settings: s}))
	symbolIn(t, err, connect.CodeInvalidArgument, "EMAIL_INVALID")
	s = relaySettings()
	s.Tls = osadminv1.EmailTls_EMAIL_TLS_UNSPECIFIED
	_, err = ec.SetEmail(ctx, connect.NewRequest(&osadminv1.SetEmailRequest{Settings: s}))
	symbolIn(t, err, connect.CodeInvalidArgument, "EMAIL_INVALID")
	if len(e.services.log()) != before {
		t.Fatal("a refused setting restarted the product")
	}
	if saved, _ := e.settings.Email(); saved.Configured() {
		t.Fatalf("a refused setting was saved: %+v", saved)
	}
}

// A product that reads no email settings has no Email page, and neither
// does a box with no product.
func TestTheEmailPageNeedsAProductThatReadsEmail(t *testing.T) {
	e := newEmailBox(t, "format: 2\n")
	ctx := context.Background()
	ec := e.client(e.alice)
	g, err := ec.GetEmail(ctx, connect.NewRequest(&osadminv1.GetEmailRequest{}))
	if err != nil || g.Msg.GetState() != "not in this product" {
		t.Fatalf("%v %v", g, err)
	}
	e.alice.stepUp("alice")
	_, err = ec.SetEmail(ctx, connect.NewRequest(&osadminv1.SetEmailRequest{Settings: relaySettings()}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "NOT_AVAILABLE")
}

// The test email goes to the typed address through the settings on the
// page, with the saved password unless another is typed; it needs a
// step-up and is audited without the password.
func TestSendTestEmail(t *testing.T) {
	e := newEmailBox(t, emailYAML)
	ctx := context.Background()
	ec := e.client(e.alice)
	if err := e.settings.SetEmail(boxsettings.Email{Host: "relay.example.org", Port: 587, From: "no-reply@sneakers.example.org", Username: "mailer", Password: relayPassword, TLS: boxsettings.TLSStartTLS, Verify: true}); err != nil {
		t.Fatal(err)
	}
	e.clk.Advance(6 * time.Minute)
	_, err := ec.SendTestEmail(ctx, connect.NewRequest(&osadminv1.SendTestEmailRequest{To: "admin@example.org"}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_STEPUP_REQUIRED")
	e.alice.stepUp("alice")
	r, err := ec.SendTestEmail(ctx, connect.NewRequest(&osadminv1.SendTestEmailRequest{To: "admin@example.org"}))
	if err != nil || !strings.Contains(r.Msg.GetAnswer(), "admin@example.org") {
		t.Fatalf("%v %v", r, err)
	}
	s := relaySettings()
	s.Host, s.Tls = "relay2.example.org", osadminv1.EmailTls_EMAIL_TLS_IMPLICIT
	if _, err := ec.SendTestEmail(ctx, connect.NewRequest(&osadminv1.SendTestEmailRequest{To: "admin@example.org", Settings: s})); err != nil {
		t.Fatal(err)
	}
	other := "typed-pass"
	if _, err := ec.SendTestEmail(ctx, connect.NewRequest(&osadminv1.SendTestEmailRequest{To: "admin@example.org", Settings: s, Password: &other})); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	sent := append([]boxsettings.Email(nil), e.sent...)
	e.mu.Unlock()
	if len(sent) != 3 || sent[0].Host != "relay.example.org" || sent[0].Password != relayPassword ||
		sent[1].Host != "relay2.example.org" || sent[1].TLS != boxsettings.TLSImplicit || sent[1].Password != relayPassword || sent[2].Password != other {
		t.Fatalf("sent %+v", sent)
	}
	a := lastEntry(t, e.log, "product.email.test-send")
	if a.Outcome != "ok" || a.Detail["to"] != "admin@example.org" || a.Detail["host"] != "relay2.example.org" {
		t.Fatalf("audit %+v", a)
	}
	// The saved settings didn't change, and nothing restarted.
	if saved, _ := e.settings.Email(); saved.Host != "relay.example.org" {
		t.Fatalf("a test changed the saved settings: %+v", saved)
	}
}
