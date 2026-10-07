// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package enrolment_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/consoletest"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/enrolment"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui/tuitest"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
)

var now = time.Date(2026, 10, 7, 18, 3, 0, 0, time.UTC)

func chrome() consoleui.Chrome {
	return consoleui.Chrome{Version: "0.1.0", Phase: "firstboot", Host: "sneakers.example.org", NTP: consoleui.NTPSynced, Now: func() time.Time { return now },
		Known: true, Protection: keycustody.Reduced(keycustody.ReasonSecureBootOff), Mode: keycustody.ModeKeyfile}
}

func page() enrolment.PageFunc {
	c := chrome()
	return func(title string, body []tui.Line, keys, prompt string) tui.Page {
		return c.Page(title, body, keys, prompt)
	}
}

const (
	fpA = "SHA256:ysknevuNI/Ng13w+vvxlQW6FcH76LnuVdAfLHqOrZRw"
	fpB = "SHA256:ZE49MXHIq3Pj+N4nEUoUfua0dqGgtmXYcekpDgbLqbw"
	fpK = "SHA256:3q2+7wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

func window(recovery bool, attempts int32, keys ...*accessv1.EnrolmentKey) *accessv1.Enrolment {
	return &accessv1.Enrolment{Open: true, Admin: "alice", Code: "7PQK-NMS9", AttemptsLeft: attempts, Recovery: recovery,
		IdleUntil: timestamppb.New(now.Add(30 * time.Minute)),
		HostKeys:  []*osadminv1.HostKey{{Type: "ssh-ed25519", Fingerprint: fpA}, {Type: "ssh-rsa", Fingerprint: fpB}},
		Keys:      keys}
}

func offered(state, via string) *accessv1.EnrolmentKey {
	return &accessv1.EnrolmentKey{Id: "k1", Fingerprint: fpK, Type: "ssh-ed25519", Comment: "alice@laptop", SourceAddress: "192.0.2.50", State: state, Via: via}
}

var noNetd = sources.NotInstalled{What: "The network service"}
var noSSH = sources.NotInstalled{What: "The SSH service"}

// Every screen of the window, as Section 2.11 lists them.
func TestEnrolmentScreens(t *testing.T) {
	pf := page()
	addrs := []string{"192.0.2.10/24", "fe80::1/64", "2001:db8::10/64"}
	cases := map[string]tui.Page{
		"waiting":               enrolment.WaitingPage(pf, enrolment.Waiting{W: window(false, 3), Addresses: addrs}, now),
		"waiting-ssh-missing":   enrolment.WaitingPage(pf, enrolment.Waiting{W: window(false, 3), Addresses: addrs, SSHErr: noSSH}, now),
		"waiting-no-address":    enrolment.WaitingPage(pf, enrolment.Waiting{W: window(false, 3), AddrErr: noNetd}, now),
		"waiting-code-failures": enrolment.WaitingPage(pf, enrolment.Waiting{W: window(false, 1), Addresses: addrs}, now),
		"waiting-new-code":      enrolment.WaitingPage(pf, enrolment.Waiting{W: window(false, 3), Addresses: addrs, Note: "Three wrong codes closed the window; this is its new code."}, now),
		"waiting-enrolled":      enrolment.WaitingPage(pf, enrolment.Waiting{W: window(false, 3, offered("accepted", access.ViaEnrol)), Addresses: addrs}, now),
		"waiting-recovery":      enrolment.WaitingPage(pf, enrolment.Waiting{W: window(true, 3), Addresses: addrs}, now),
		"offered":               enrolment.OfferedPage(pf, window(false, 3), offered("waiting", access.ViaEnrol), ""),
		"offered-typed":         enrolment.OfferedPage(pf, window(false, 3), offered("waiting", access.ViaTyped), "Type yes to store the key, or no to refuse it."),
		"offered-recovery":      enrolment.OfferedPage(pf, window(true, 3), offered("waiting", access.ViaEnrol), ""),
		"closed":                enrolment.ClosedPage(pf, &accessv1.Enrolment{Admin: "alice", ClosedReason: "idle", Enrolled: 1}),
		"type":                  enrolment.TypePage(pf, window(false, 3), ""),
		"type-refused":          enrolment.TypePage(pf, window(false, 3), "ACCESS_KEY_WEAK: RSA keys need at least 3072 bits"),
		"url":                   enrolment.URLPage(pf, window(false, 3), ""),
		"fetching":              enrolment.FetchingPage(pf, window(false, 3), "https://forge.example.org/alice.keys"),
		"fetched": enrolment.FetchedPage(pf, window(false, 3), "https://forge.example.org/alice.keys", access.Fetched{
			Keys:    []access.Key{{Fingerprint: fpK, Type: "ssh-ed25519", Comment: "laptop"}, {Fingerprint: fpA, Type: "ssh-ed25519", Comment: "desk"}},
			Refused: []string{"ACCESS_KEY_WEAK: DSA keys aren't accepted"}}),
		"fetch-failed": enrolment.FetchFailedPage(pf, window(false, 3), "https://forge.example.org/alice.keys", errors.New(`Get "https://forge.example.org/alice.keys": dial tcp: lookup forge.example.org: no such host`)),
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) { tuitest.Golden(t, "enrol-"+name, p) })
	}
}

func deps(b *consoletest.Box, fetch func(context.Context, string) (access.Fetched, error)) enrolment.Deps {
	return enrolment.Deps{
		Window:    b.Window(),
		Fetch:     fetch,
		Addresses: func(context.Context) ([]string, error) { return []string{"192.0.2.10/24"}, nil },
		SSH:       func(context.Context) error { return nil },
		Page:      page(),
		Now:       func() time.Time { return now },
	}
}

// Over SSH: a key gives the code, the console shows it, the typed yes
// stores it, and Done closes the window.
func TestAKeyOverSSHIsStoredWithTheTypedYes(t *testing.T) {
	b := consoletest.NewBox(t, "alice")
	d := tuitest.New(t)
	done := tuitest.Run(context.Background(), func(ctx context.Context) error {
		n, err := enrolment.Run(ctx, d.UI, deps(b, nil), "alice", false)
		if err == nil && n != 1 {
			err = errors.New("enrolled count")
		}
		return err
	})
	d.Expect(t, "ssh enrol@192.0.2.10")
	line, fp := consoletest.Key(t, "alice@laptop")
	d.Type(t, "d")
	d.Expect(t, "Enrol at least one key first.")
	if _, err := b.Enrol.Submit(b.Enrol.Get().Code, line, "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	d.Expect(t, fp)
	d.Type(t, "maybe")
	d.Expect(t, "Type yes to store the key, or no to refuse it.")
	d.Type(t, "yes")
	d.Expect(t, "Keys enrolled so far: 1")
	d.Type(t, "d")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	st := b.Store.Read()
	a, _ := st.Admin("alice")
	if len(a.Keys) != 1 || a.Keys[0].Fingerprint != fp || b.Enrol.IsOpen() {
		t.Fatalf("%+v open=%v", a, b.Enrol.IsOpen())
	}
}

// Without sshd the screen says so and the key is typed on the console;
// Recover access stores it under the hold.
func TestATypedKeyThroughRecoverAccess(t *testing.T) {
	b := consoletest.NewBox(t, "alice")
	d := tuitest.New(t)
	dp := deps(b, nil)
	dp.SSH = func(context.Context) error { return noSSH }
	done := tuitest.Run(context.Background(), func(ctx context.Context) error {
		_, err := enrolment.Run(ctx, d.UI, dp, "alice", true)
		return err
	})
	d.Expect(t, "The SSH service isn't installed in this build yet")
	d.Type(t, "t")
	d.Expect(t, "Type or paste one public key")
	d.Type(t, "ssh-dss AAAAB3NzaC1kc3MAAACBAP")
	d.Expect(t, "ACCESS_KEY")
	line, fp := consoletest.Key(t, "alice@spare")
	d.Type(t, line)
	d.Expect(t, "typed on the console")
	d.Type(t, "yes")
	d.Expect(t, "Keys enrolled so far: 1")
	d.Type(t, "d")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	st := b.Store.Read()
	a, _ := st.Admin("alice")
	if len(a.Keys) != 1 || a.Keys[0].Fingerprint != fp || a.Keys[0].Via != access.ViaConsoleRecovery || a.ApprovalHoldUntil == nil {
		t.Fatalf("%+v", a)
	}
}

// Fetched keys are listed, then each is confirmed or refused.
func TestFetchedKeysAreConfirmedOneByOne(t *testing.T) {
	b := consoletest.NewBox(t, "alice")
	d := tuitest.New(t)
	l1, fp1 := consoletest.Key(t, "laptop")
	l2, fp2 := consoletest.Key(t, "desk")
	fetch := func(_ context.Context, url string) (access.Fetched, error) {
		if url != "https://forge.example.org/alice.keys" {
			return access.Fetched{}, errors.New("no such host")
		}
		k1, _ := access.ParseLoginKey(l1)
		k2, _ := access.ParseLoginKey(l2)
		return access.Fetched{Keys: []access.Key{k1, k2}}, nil
	}
	done := tuitest.Run(context.Background(), func(ctx context.Context) error {
		_, err := enrolment.Run(ctx, d.UI, deps(b, fetch), "alice", false)
		return err
	})
	d.Expect(t, "ssh enrol@")
	d.Type(t, "f")
	d.Expect(t, "URL:")
	d.Type(t, "https://forge.example.org/nobody.keys")
	d.Expect(t, "failed")
	d.Type(t, "")
	d.Type(t, "f")
	d.Type(t, "https://forge.example.org/alice.keys")
	d.Expect(t, "has 2 acceptable key(s)")
	d.Type(t, "")
	d.Expect(t, fp1)
	d.Type(t, "yes")
	d.Expect(t, fp2)
	d.Type(t, "no")
	d.Expect(t, "Keys enrolled so far: 1")
	d.Type(t, "d")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	st := b.Store.Read()
	a, _ := st.Admin("alice")
	if len(a.Keys) != 1 || a.Keys[0].Fingerprint != fp1 || a.Keys[0].Via != access.ViaURL {
		t.Fatalf("%+v", a)
	}
}
