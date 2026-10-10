// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
)

func statusOf(t *testing.T, st osadminv1connect.StatusServiceClient) *osadminv1.GetStatusResponse {
	t.Helper()
	s, err := st.GetStatus(context.Background(), connect.NewRequest(&osadminv1.GetStatusRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return s.Msg
}

func hideNotice(t *testing.T, st osadminv1connect.StatusServiceClient, reason string) bool {
	t.Helper()
	r, err := st.HideProtectionNotice(context.Background(), connect.NewRequest(&osadminv1.HideProtectionNoticeRequest{Reason: reason}))
	if err != nil {
		t.Fatal(err)
	}
	return r.Msg.GetHidden()
}

// Any signed-in admin may hide the reduced-protection notice with no
// step-up. Status then leaves the banner out but still gives the level,
// the reason and how to raise it, and the hiding is audited.
func TestAnAdminHidesTheReducedProtectionNotice(t *testing.T) {
	b := newBox(t, true)
	bob := b.browser()
	bob.signIn("bob")
	b.init.level = initv1.ProtectionLevel_PROTECTION_LEVEL_REDUCED
	st := osadminv1connect.NewStatusServiceClient(bob.hc, b.ts.URL)

	before := statusOf(t, st)
	if !kinds(before.GetWarnings())[osadminv1.WarningKind_WARNING_KIND_REDUCED_PROTECTION] || before.GetProtectionNotice().GetHidden() {
		t.Fatalf("before hiding: %v", before)
	}
	if !strings.Contains(before.GetProtectionDetail(), "fixed until a reinstall") {
		t.Fatalf("protection detail %q", before.GetProtectionDetail())
	}

	if !hideNotice(t, st, "no-tpm") {
		t.Fatal("the notice wasn't hidden")
	}
	after := statusOf(t, st)
	if kinds(after.GetWarnings())[osadminv1.WarningKind_WARNING_KIND_REDUCED_PROTECTION] {
		t.Fatalf("the hidden notice is still a warning: %v", after.GetWarnings())
	}
	if after.GetProtection() != osadminv1.Protection_PROTECTION_REDUCED || after.GetProtectionReason() != "no-tpm" || after.GetProtectionDetail() != before.GetProtectionDetail() {
		t.Fatalf("Status lost the protection line: %v", after)
	}
	if n := after.GetProtectionNotice(); !n.GetHidden() || n.GetHiddenBy() != "bob" || n.GetHiddenAt() == nil {
		t.Fatalf("protection notice %v", n)
	}
	if !kinds(after.GetWarnings())[osadminv1.WarningKind_WARNING_KIND_SELF_SIGNED_TLS] {
		t.Fatalf("other warnings went too: %v", after.GetWarnings())
	}
	e := lastEntry(t, b.log, "status.protection-notice.hide")
	if e.Actor != "bob" || e.Outcome != "ok" || e.Target != "protection notice" || e.Detail["level"] != "reduced" || e.Detail["reason"] != "no-tpm" {
		t.Fatalf("audit %+v", e)
	}
}

// The notice comes back when the reason changes, a click on a notice that
// no longer matches hides nothing, and full protection clears the
// acknowledgement so a later drop shows it again.
func TestTheHiddenNoticeIsTiedToTheLevelAndReason(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	b.init.level = initv1.ProtectionLevel_PROTECTION_LEVEL_REDUCED
	st := osadminv1connect.NewStatusServiceClient(alice.hc, b.ts.URL)
	reduced := func() bool {
		return kinds(statusOf(t, st).GetWarnings())[osadminv1.WarningKind_WARNING_KIND_REDUCED_PROTECTION]
	}

	if !hideNotice(t, st, "no-tpm") || reduced() {
		t.Fatal("not hidden")
	}
	b.init.reason = "secure-boot-off"
	if !reduced() {
		t.Fatal("another reason must show the notice again")
	}
	if hideNotice(t, st, "no-tpm") || !reduced() {
		t.Fatal("hiding a reason the box no longer has must hide nothing")
	}

	b.init.reason = ""
	if reduced() {
		t.Fatal("the acknowledged reason is back and stays hidden")
	}
	b.init.level = initv1.ProtectionLevel_PROTECTION_LEVEL_FULL
	if s := statusOf(t, st); s.GetProtectionNotice().GetHidden() || s.GetProtectionDetail() != "" {
		t.Fatalf("at full protection: %v", s)
	}
	if hideNotice(t, st, "") {
		t.Fatal("there's nothing to hide at full protection")
	}
	b.init.level = initv1.ProtectionLevel_PROTECTION_LEVEL_REDUCED
	if !reduced() {
		t.Fatal("full protection must clear the acknowledgement")
	}
}

// The acknowledgement is kept on the state volume: a new osadmin on the
// same volume (a reboot or an update) still leaves the notice out.
func TestTheHiddenNoticeSurvivesARestart(t *testing.T) {
	var opts osadmin.Options
	b := newBox(t, false, func(_ *box, o *osadmin.Options) { opts = *o })
	alice := b.browser()
	alice.signIn("alice")
	b.init.level = initv1.ProtectionLevel_PROTECTION_LEVEL_REDUCED
	if !hideNotice(t, osadminv1connect.NewStatusServiceClient(alice.hc, b.ts.URL), "no-tpm") {
		t.Fatal("not hidden")
	}

	b.srv.Close()
	b.ts.Close()
	b.srv = osadmin.New(opts)
	b.ts = httptest.NewTLSServer(b.srv.Handler())
	t.Cleanup(b.ts.Close)
	t.Cleanup(b.srv.Close)
	br := b.browser()
	br.signIn("alice")
	s := statusOf(t, osadminv1connect.NewStatusServiceClient(br.hc, b.ts.URL))
	if kinds(s.GetWarnings())[osadminv1.WarningKind_WARNING_KIND_REDUCED_PROTECTION] || s.GetProtectionNotice().GetHiddenBy() != "alice" {
		t.Fatalf("after a restart: %v", s)
	}
}

// Hiding the notice needs a signed-in admin.
func TestHidingTheNoticeNeedsASession(t *testing.T) {
	b := newBox(t, false)
	b.init.level = initv1.ProtectionLevel_PROTECTION_LEVEL_REDUCED
	_, err := osadminv1connect.NewStatusServiceClient(b.browser().hc, b.ts.URL).HideProtectionNotice(context.Background(), connect.NewRequest(&osadminv1.HideProtectionNoticeRequest{Reason: "no-tpm"}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("want unauthenticated, got %v", err)
	}
}
