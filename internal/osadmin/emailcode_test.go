// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
)

var sixDigits = regexp.MustCompile(`^[0-9]{6}$`)

// sendTest sends the test message for s with the saved password, or pw.
func (e *emailBox) sendTest(t *testing.T, s *osadminv1.EmailSettings, pw *string) {
	t.Helper()
	e.alice.stepUp("alice")
	if _, err := e.client(e.alice).SendTestEmail(context.Background(), connect.NewRequest(&osadminv1.SendTestEmailRequest{To: "admin@example.org", Settings: s, Password: pw})); err != nil {
		t.Fatal(err)
	}
}

func (e *emailBox) check(s *osadminv1.EmailSettings, pw *string, code string) error {
	e.alice.stepUp("alice")
	_, err := e.client(e.alice).CheckEmailCode(context.Background(), connect.NewRequest(&osadminv1.CheckEmailCodeRequest{Settings: s, Password: pw, Code: code}))
	return err
}

func (e *emailBox) save(s *osadminv1.EmailSettings, pw *string) error {
	e.alice.stepUp("alice")
	_, err := e.client(e.alice).SetEmail(context.Background(), connect.NewRequest(&osadminv1.SetEmailRequest{Settings: s, Password: pw}))
	return err
}

// SetEmail refuses a relay that no test email has proved, and takes it once
// the code from the test message is typed back.
func TestSetEmailNeedsTheTestEmailsCode(t *testing.T) {
	e := newEmailBox(t, emailYAML)
	pw := relayPassword
	s := relaySettings()
	symbolIn(t, e.save(s, &pw), connect.CodeFailedPrecondition, "EMAIL_NOT_TESTED")
	e.sendTest(t, s, &pw)
	code := e.lastCode()
	if !sixDigits.MatchString(code) {
		t.Fatalf("the test message's code %q isn't 6 digits", code)
	}
	symbolIn(t, e.save(s, &pw), connect.CodeFailedPrecondition, "EMAIL_NOT_TESTED")
	if err := e.check(s, &pw, code); err != nil {
		t.Fatal(err)
	}
	if err := e.save(s, &pw); err != nil {
		t.Fatal(err)
	}
	if r := e.restarted(t); r == "" {
		t.Fatal("not applied")
	}
}

// A wrong code is refused with its own code; four wrong tries leave the
// right code working, and five drop the code, so the right one is then
// expired.
func TestAWrongEmailCodeCountsAgainstFiveTries(t *testing.T) {
	e := newEmailBox(t, emailYAML)
	pw := relayPassword
	s := relaySettings()
	e.sendTest(t, s, &pw)
	right := e.lastCode()
	wrong := "000000"
	if right == wrong {
		wrong = "111111"
	}
	for range 4 {
		symbolIn(t, e.check(s, &pw, wrong), connect.CodeInvalidArgument, "EMAIL_CODE_WRONG")
	}
	if err := e.check(s, &pw, right); err != nil {
		t.Fatalf("the right code after four wrong tries: %v", err)
	}

	e.sendTest(t, s, &pw)
	right = e.lastCode()
	if right == wrong {
		wrong = "222222"
	}
	for range 5 {
		symbolIn(t, e.check(s, &pw, wrong), connect.CodeInvalidArgument, "EMAIL_CODE_WRONG")
	}
	symbolIn(t, e.check(s, &pw, right), connect.CodeFailedPrecondition, "EMAIL_CODE_EXPIRED")
}

// The code is good for ten minutes, once.
func TestAnEmailCodeExpiresAndIsUsedOnce(t *testing.T) {
	e := newEmailBox(t, emailYAML)
	pw := relayPassword
	s := relaySettings()
	e.sendTest(t, s, &pw)
	e.clk.Advance(11 * time.Minute)
	symbolIn(t, e.check(s, &pw, e.lastCode()), connect.CodeFailedPrecondition, "EMAIL_CODE_EXPIRED")

	e.sendTest(t, s, &pw)
	code := e.lastCode()
	if err := e.check(s, &pw, code); err != nil {
		t.Fatal(err)
	}
	symbolIn(t, e.check(s, &pw, code), connect.CodeFailedPrecondition, "EMAIL_CODE_EXPIRED")
	// The pass lasts ten minutes too.
	e.clk.Advance(11 * time.Minute)
	symbolIn(t, e.save(s, &pw), connect.CodeFailedPrecondition, "EMAIL_NOT_TESTED")
}

// A pass is for exactly the settings and the password tested: an edit after
// the code, or another password, needs a new test.
func TestAPassIsForExactlyTheSettingsTested(t *testing.T) {
	e := newEmailBox(t, emailYAML)
	pw := relayPassword
	s := relaySettings()
	e.passFor(t, s, &pw)

	edited := relaySettings()
	edited.Host = "relay2.example.org"
	symbolIn(t, e.save(edited, &pw), connect.CodeFailedPrecondition, "EMAIL_NOT_TESTED")
	other := "another-password"
	symbolIn(t, e.save(s, &other), connect.CodeFailedPrecondition, "EMAIL_NOT_TESTED")
	// A code for one set of settings doesn't pass another.
	e.sendTest(t, s, &pw)
	symbolIn(t, e.check(edited, &pw, e.lastCode()), connect.CodeFailedPrecondition, "EMAIL_CODE_EXPIRED")
	// The tested settings still save.
	e.passFor(t, s, &pw)
	if err := e.save(s, &pw); err != nil {
		t.Fatal(err)
	}
}

// The saved password counts as part of the settings: a test and a save that
// both leave the password out are for the same settings.
func TestASavedPasswordIsPartOfThePass(t *testing.T) {
	e := newEmailBox(t, emailYAML)
	pw := relayPassword
	s := relaySettings()
	e.passFor(t, s, &pw)
	if err := e.save(s, &pw); err != nil {
		t.Fatal(err)
	}
	e.restarted(t)
	e.passFor(t, s, nil)
	if err := e.save(s, nil); err != nil {
		t.Fatal(err)
	}
	e.restarted(t)
	// The saved password changed under the pass: a new test is needed.
	e.passFor(t, s, nil)
	changed := "changed-password"
	symbolIn(t, e.save(s, &changed), connect.CodeFailedPrecondition, "EMAIL_NOT_TESTED")
}

// Turning the product's mail off has no relay to test.
func TestTurningTheRelayOffNeedsNoTest(t *testing.T) {
	e := newEmailBox(t, emailYAML)
	pw := relayPassword
	s := relaySettings()
	e.passFor(t, s, &pw)
	if err := e.save(s, &pw); err != nil {
		t.Fatal(err)
	}
	e.restarted(t)
	off := relaySettings()
	off.Host, off.Username = "", ""
	empty := ""
	if err := e.save(off, &empty); err != nil {
		t.Fatal(err)
	}
	e.restarted(t)
}

// The check is audited without the code or the password.
func TestTheCodeCheckIsAuditedWithoutTheCode(t *testing.T) {
	e := newEmailBox(t, emailYAML)
	pw := relayPassword
	s := relaySettings()
	e.sendTest(t, s, &pw)
	code := e.lastCode()
	if err := e.check(s, &pw, code); err != nil {
		t.Fatal(err)
	}
	a := lastEntry(t, e.log, "product.email.code-check")
	if got := fmt.Sprintf("%+v", a); strings.Contains(got, code) || strings.Contains(got, relayPassword) {
		t.Fatalf("the audit entry carries the code or the password: %s", got)
	}
}
