// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"bufio"
	"context"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
)

func kinds(ws []*osadminv1.Warning) map[osadminv1.WarningKind]bool {
	out := map[osadminv1.WarningKind]bool{}
	for _, w := range ws {
		out[w.GetKind()] = true
	}
	return out
}

func TestStatus(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	b.netd.settings.AllowList = []string{"192.0.2.0/24"}
	st := osadminv1connect.NewStatusServiceClient(alice.hc, b.ts.URL)
	s, err := st.GetStatus(ctx, connect.NewRequest(&osadminv1.GetStatusRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	m := s.Msg
	if m.GetProtection() != osadminv1.Protection_PROTECTION_FULL || m.GetCustodyMode() != "tpm" || m.GetRunningVersion() != "0.1.0" || m.GetHostname() != "box1.sneakers.example.org" || m.GetPhase() != "firstboot" {
		t.Fatalf("%v", m)
	}
	if m.GetDisk().GetTotalBytes() == 0 {
		t.Fatal("disk use")
	}
	w := kinds(m.GetWarnings())
	if !w[osadminv1.WarningKind_WARNING_KIND_SELF_SIGNED_TLS] || w[osadminv1.WarningKind_WARNING_KIND_EXPOSURE] || w[osadminv1.WarningKind_WARNING_KIND_NTP_UNSYNCED] {
		t.Fatalf("warnings %v", m.GetWarnings())
	}

	b.netd.mgmt = []string{"198.51.100.7"}
	b.netd.settings.AllowList = []string{"0.0.0.0/0"}
	b.netd.ntp = false
	b.init.level = initv1.ProtectionLevel_PROTECTION_LEVEL_REDUCED
	used := b.clk.Now().Add(-time.Hour)
	if err := b.store.Update(func(s *access.State) error { s.LastRecoverAccess = &used; return nil }); err != nil {
		t.Fatal(err)
	}
	s, err = st.GetStatus(ctx, connect.NewRequest(&osadminv1.GetStatusRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	w = kinds(s.Msg.GetWarnings())
	for _, k := range []osadminv1.WarningKind{osadminv1.WarningKind_WARNING_KIND_EXPOSURE, osadminv1.WarningKind_WARNING_KIND_NTP_UNSYNCED, osadminv1.WarningKind_WARNING_KIND_REDUCED_PROTECTION, osadminv1.WarningKind_WARNING_KIND_CONSOLE_RECOVERY} {
		if !w[k] {
			t.Errorf("missing %v", k)
		}
	}
}

func TestSecureBootSettingNeedsTheHostName(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	st := osadminv1connect.NewStatusServiceClient(alice.hc, b.ts.URL)
	ctx := context.Background()
	_, err := st.SetSecureBoot(ctx, connect.NewRequest(&osadminv1.SetSecureBootRequest{On: false, ConfirmHostname: "wrong"}))
	symbolIn(t, err, connect.CodeInvalidArgument, "ACCESS_CONFIRM")
	if b.init.secureBoot != nil {
		t.Fatal("nothing changes without the confirmation")
	}
	if _, err := st.SetSecureBoot(ctx, connect.NewRequest(&osadminv1.SetSecureBootRequest{On: false, ConfirmHostname: "box1.sneakers.example.org"})); err != nil {
		t.Fatal(err)
	}
	if b.init.secureBoot == nil || *b.init.secureBoot {
		t.Fatal("init told")
	}
	if e := lastEntry(t, b.log, "status.secure-boot.set"); e.Outcome != "ok" || e.Detail["on"] != "off" {
		t.Fatalf("%+v", e)
	}
}

func TestNetworkWithAutoRevert(t *testing.T) {
	b := newBox(t, true)
	ctx := context.Background()
	bob := b.browser()
	bob.signIn("bob")
	set := defaultSettings()
	set.Hostname = "box2"
	_, err := osadminv1connect.NewNetworkServiceClient(bob.hc, b.ts.URL).SetNetwork(ctx, connect.NewRequest(&osadminv1.SetNetworkRequest{Settings: set}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")

	alice := b.browser()
	alice.signIn("alice")
	nc := osadminv1connect.NewNetworkServiceClient(alice.hc, b.ts.URL)
	bad := defaultSettings()
	bad.AllowList = []string{"not a prefix"}
	_, err = nc.SetNetwork(ctx, connect.NewRequest(&osadminv1.SetNetworkRequest{Settings: bad}))
	symbolIn(t, err, connect.CodeInvalidArgument, "NET_INVALID")
	res, err := nc.SetNetwork(ctx, connect.NewRequest(&osadminv1.SetNetworkRequest{Settings: set}))
	if err != nil || res.Msg.GetRevertAfterSeconds() != 120 {
		t.Fatalf("%v %v", res, err)
	}
	g, err := nc.GetNetwork(ctx, connect.NewRequest(&osadminv1.GetNetworkRequest{}))
	if err != nil || !g.Msg.GetPending() || g.Msg.GetSettings().GetHostname() != "box2" {
		t.Fatalf("%v %v", g, err)
	}
	if _, err := nc.ConfirmNetwork(ctx, connect.NewRequest(&osadminv1.ConfirmNetworkRequest{Token: res.Msg.GetToken()})); err != nil {
		t.Fatal(err)
	}
	if b.netd.confirmed != 1 {
		t.Fatal("confirmed")
	}
	ch, err := nc.RunChecks(ctx, connect.NewRequest(&osadminv1.RunChecksRequest{}))
	if err != nil || len(ch.Msg.GetChecks()) != 1 || ch.Msg.GetChecks()[0].GetState() != netdv1.CheckState_CHECK_STATE_OK {
		t.Fatalf("%v %v", ch, err)
	}
}

func TestGracefulPower(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	pc := osadminv1connect.NewPowerServiceClient(alice.hc, b.ts.URL)
	gp, err := pc.GetPower(ctx, connect.NewRequest(&osadminv1.GetPowerRequest{}))
	if err != nil || len(gp.Msg.GetSessions()) != 1 || gp.Msg.GetSessions()[0].GetAdmin() != "alice" {
		t.Fatalf("the active-session warning lists sessions: %v %v", gp, err)
	}
	if _, err := pc.Reboot(ctx, connect.NewRequest(&osadminv1.RebootRequest{})); err != nil {
		t.Fatal(err)
	}
	if _, err := pc.Shutdown(ctx, connect.NewRequest(&osadminv1.ShutdownRequest{})); err != nil {
		t.Fatal(err)
	}
	if b.init.reboots != 1 || b.init.poweroffs != 1 {
		t.Fatal("init told")
	}
	if e := lastEntry(t, b.log, "power.reboot"); e.Detail["mode"] != "graceful" || e.Detail["surface"] != "8443" || e.Actor != "alice" {
		t.Fatalf("%+v", e)
	}
	b.clk.Advance(6 * time.Minute)
	_, err = pc.Reboot(ctx, connect.NewRequest(&osadminv1.RebootRequest{}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_STEPUP_REQUIRED")
}

func TestAuditListAndExport(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	ac := osadminv1connect.NewAuditServiceClient(alice.hc, b.ts.URL)
	for range 3 {
		_, _ = alice.access().AddKey(ctx, connect.NewRequest(&osadminv1.AddKeyRequest{Admin: "alice", PublicKey: newKey(t).line}))
	}
	l, err := ac.ListEvents(ctx, connect.NewRequest(&osadminv1.ListEventsRequest{Limit: 2, Action: "access."}))
	if err != nil || len(l.Msg.GetEvents()) != 2 || !l.Msg.GetChainOk() || l.Msg.GetNextPageToken() == "" {
		t.Fatalf("%v %v", l, err)
	}
	next, err := ac.ListEvents(ctx, connect.NewRequest(&osadminv1.ListEventsRequest{Limit: 2, Action: "access.", PageToken: l.Msg.GetNextPageToken()}))
	if err != nil || len(next.Msg.GetEvents()) != 1 || next.Msg.GetNextPageToken() != "" {
		t.Fatalf("%v %v", next, err)
	}
	resp, err := alice.hc.Get(b.ts.URL + "/export/audit-log")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", resp, err)
	}
	n := 0
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		n++
	}
	_ = resp.Body.Close()
	if n < 5 {
		t.Fatalf("exported %d lines", n)
	}
	anon, err := b.browser().hc.Get(b.ts.URL + "/export/audit-log")
	if err != nil || anon.StatusCode != 401 {
		t.Fatalf("export needs a session: %v %v", anon, err)
	}
	_ = anon.Body.Close()
}

// Reduced protection on Status is said in plain words, with how to raise
// it later: the same text as the console's.
func TestStatusSaysHowToRaiseReducedProtection(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	b.init.level = initv1.ProtectionLevel_PROTECTION_LEVEL_REDUCED
	s, err := osadminv1connect.NewStatusServiceClient(alice.hc, b.ts.URL).GetStatus(context.Background(), connect.NewRequest(&osadminv1.GetStatusRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range s.Msg.GetWarnings() {
		if w.GetKind() != osadminv1.WarningKind_WARNING_KIND_REDUCED_PROTECTION {
			continue
		}
		for _, want := range []string{"At-rest protection: reduced (no TPM).", "fixed until a reinstall"} {
			if !strings.Contains(w.GetDetail(), want) {
				t.Errorf("the warning %q lacks %q", w.GetDetail(), want)
			}
		}
		return
	}
	t.Fatalf("no reduced-protection warning in %v", s.Msg.GetWarnings())
}
