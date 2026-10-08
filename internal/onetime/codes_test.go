// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package onetime_test

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/onetime"
)

type fakeSealer struct {
	items map[string][]byte
	fail  bool
}

func (f *fakeSealer) Seal(name string, secret []byte) error {
	if f.fail {
		return errors.New("custody is down")
	}
	f.items[name] = append([]byte(nil), secret...)
	return nil
}

func (f *fakeSealer) Unseal(name string) ([]byte, bool, error) {
	b, ok := f.items[name]
	return b, ok, nil
}

func newCodes(t *testing.T) (*onetime.Codes, *clock.Fake, *int) {
	t.Helper()
	c, clk, changes, _ := newSealedCodes(t)
	return c, clk, changes
}

func newSealedCodes(t *testing.T) (*onetime.Codes, *clock.Fake, *int, *fakeSealer) {
	t.Helper()
	clk := clock.NewFake()
	changes := 0
	sealer := &fakeSealer{items: map[string][]byte{}}
	return onetime.NewCodes(clk, func() { changes++ }, sealer, nil), clk, &changes, sealer
}

var setupCodeRE = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$`)

func TestTheSetupCodeIsSixteenCrockfordCharacters(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		c, _, _ := newCodes(t)
		sc := c.Setup().Value
		if !setupCodeRE.MatchString(sc) {
			t.Fatalf("setup code %q isn't XXXX-XXXX-XXXX-XXXX in Crockford base32", sc)
		}
		if strings.ContainsAny(sc, "ILOU") {
			t.Fatalf("setup code %q has I, L, O or U", sc)
		}
		seen[sc] = true
	}
	if len(seen) < 200 {
		t.Fatalf("200 setup codes held %d distinct values", len(seen))
	}
}

func TestTheSetupCodeIgnoresCaseAndDashesAndReadsLookAlikes(t *testing.T) {
	for _, typed := range []func(string) string{
		strings.ToLower,
		func(s string) string { return strings.ReplaceAll(s, "-", "") },
		func(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "0", "o"), "1", "l") },
		func(s string) string { return strings.ReplaceAll(s, "1", "I") },
	} {
		c, _, _ := newCodes(t)
		sc := c.Setup().Value
		if got, err := c.Redeem(typed(sc), "192.0.2.50"); err != nil || got.Kind != onetime.KindSetup {
			t.Fatalf("%q typed as %q: %+v %v", sc, typed(sc), got, err)
		}
	}
}

func TestTheSetupCodeWorksOnceAndForSixtyMinutes(t *testing.T) {
	c, clk, changes := newCodes(t)
	sc := c.Setup()
	if onetime.SetupLifetime != 60*time.Minute {
		t.Fatalf("the setup code lasts %v", onetime.SetupLifetime)
	}
	if sc.Value == "" || sc.AttemptsLeft != onetime.MaxAttempts || !sc.Expires.Equal(clk.Now().Add(60*time.Minute)) {
		t.Fatalf("setup code %+v", sc)
	}
	clk.Advance(60*time.Minute - time.Second)
	got, err := c.Redeem(strings.ToLower(sc.Value), "192.0.2.50")
	if err != nil || got.Kind != onetime.KindSetup {
		t.Fatalf("redeem a second before the hour: %+v %v", got, err)
	}
	if _, err := c.Redeem(sc.Value, "192.0.2.51"); !codes.Is(err, codes.SetupCode) {
		t.Fatalf("a second redeem: %v", err)
	}
	st := c.Setup()
	if !st.InUse || st.Source != "192.0.2.50" || st.Value != "" {
		t.Fatalf("an in-use code is shown no more: %+v", st)
	}
	if *changes == 0 {
		t.Fatal("redeeming didn't tell the console")
	}
}

func TestTheSetupCodeExpiresAfterSixtyMinutes(t *testing.T) {
	c, clk, changes := newCodes(t)
	old := c.Setup()
	before := *changes
	clk.Advance(60 * time.Minute)
	if _, err := c.Redeem(old.Value, "192.0.2.50"); !codes.Is(err, codes.SetupCode) {
		t.Fatalf("an expired code: %v", err)
	}
	if fresh := c.Setup(); fresh.Value == old.Value || fresh.Value == "" {
		t.Fatalf("no new code after expiry: %+v", fresh)
	}
	if *changes == before {
		t.Fatal("the new code wasn't announced")
	}
}

func TestFiveWrongTriesLockTheSetupCode(t *testing.T) {
	c, _, _ := newCodes(t)
	first := c.Setup()
	for i := range onetime.MaxAttempts {
		_, err := c.Redeem("0000-0000-0000-0000", "192.0.2.50")
		if !codes.Is(err, codes.SetupCode) {
			t.Fatalf("try %d: %v", i, err)
		}
	}
	locked := c.Setup()
	if !locked.Locked || locked.Value != "" || locked.AttemptsLeft != 0 {
		t.Fatalf("after five wrong tries %+v", locked)
	}
	if _, err := c.Redeem(first.Value, "192.0.2.50"); !codes.Is(err, codes.SetupCode) {
		t.Fatalf("the right code after the lockout: %v", err)
	}
	if _, err := c.Redeem("not a code", "192.0.2.50"); !codes.Is(err, codes.SetupCode) {
		t.Fatalf("garbage: %v", err)
	}
	c.ResetSetup()
	next := c.Setup()
	if next.Locked || next.Value == "" || next.Value == first.Value || next.AttemptsLeft != onetime.MaxAttempts {
		t.Fatalf("the console's new code %+v", next)
	}
}

func TestTheSetupCodeIsSealedAndSurvivesARestart(t *testing.T) {
	c, clk, _, sealer := newSealedCodes(t)
	sc := c.Setup()
	if _, err := c.Redeem("0000-0000-0000-0000", "192.0.2.50"); err == nil {
		t.Fatal("a wrong code worked")
	}
	if _, ok := sealer.items[onetime.SealedName]; !ok {
		t.Fatal("the setup code wasn't sealed")
	}
	again := onetime.NewCodes(clk, nil, sealer, nil).Setup()
	if again.Value != sc.Value || !again.Expires.Equal(sc.Expires) || again.AttemptsLeft != onetime.MaxAttempts-1 {
		t.Fatalf("after a restart %+v, want %+v with one try used", again, sc)
	}
}

func TestARedeemedSetupCodeIsGoneAfterARestart(t *testing.T) {
	c, clk, _, sealer := newSealedCodes(t)
	sc := c.Setup()
	if _, err := c.Redeem(sc.Value, "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	again := onetime.NewCodes(clk, nil, sealer, nil)
	if _, err := again.Redeem(sc.Value, "192.0.2.50"); err == nil {
		t.Fatal("a redeemed setup code worked again after a restart")
	}
	if n := again.Setup(); n.Value == "" || n.Value == sc.Value {
		t.Fatalf("after a restart %+v", n)
	}
}

func TestTheSetupCodeIsDestroyedOnceTheFirstAdminExists(t *testing.T) {
	c, clk, _, sealer := newSealedCodes(t)
	sc := c.Setup()
	if _, err := c.Redeem(sc.Value, "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	c.ConsumeSetup()
	b := sealer.items[onetime.SealedName]
	if len(b) == 0 || strings.Contains(string(b), sc.Value) {
		t.Fatalf("the sealed item after the first admin: %q", b)
	}
	if st := c.Setup(); st.Value != "" || !st.Consumed {
		t.Fatalf("a consumed code %+v", st)
	}
	c.ResetSetup()
	if st := c.Setup(); st.Value != "" {
		t.Fatal("a reset after the first admin made a new setup code")
	}
	again := onetime.NewCodes(clk, nil, sealer, nil)
	if st := again.Setup(); st.Value != "" || !st.Consumed {
		t.Fatalf("a restart after the first admin brought a setup code back: %+v", st)
	}
	if _, err := again.Redeem(sc.Value, "192.0.2.50"); err == nil {
		t.Fatal("the destroyed setup code worked")
	}
}

func TestTheRecoverAccessCodeFollowsTheSetupCodesRules(t *testing.T) {
	c, clk, _, sealer := newSealedCodes(t)
	c.ConsumeSetup()
	r := c.BeginRecover()
	if !setupCodeRE.MatchString(r.Value) || !r.Expires.Equal(clk.Now().Add(60*time.Minute)) || r.AttemptsLeft != onetime.MaxAttempts {
		t.Fatalf("recover code %+v", r)
	}
	if !strings.Contains(string(sealer.items[onetime.SealedName]), r.Value) {
		t.Fatal("the Recover access code wasn't sealed")
	}
	again := onetime.NewCodes(clk, nil, sealer, nil)
	if got, ok := again.Recover(); !ok || got.Value != r.Value {
		t.Fatalf("after a restart %+v %v", got, ok)
	}
	if _, err := again.Redeem(r.Value, "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sealer.items[onetime.SealedName]), r.Value) {
		t.Fatal("a used Recover access code is still sealed")
	}
}

func TestASetupCodeThatCantBeSealedIsNotShown(t *testing.T) {
	sealer := &fakeSealer{items: map[string][]byte{}, fail: true}
	c := onetime.NewCodes(clock.NewFake(), nil, sealer, nil)
	if sc := c.Setup(); sc.Value != "" {
		t.Fatalf("an unsealed setup code was shown: %+v", sc)
	}
	sealer.fail = false
	if sc := c.Setup(); sc.Value == "" {
		t.Fatal("no setup code once custody is back")
	}
}

func TestResetEndsTheInUseCode(t *testing.T) {
	c, _, _ := newCodes(t)
	sc := c.Setup()
	if _, err := c.Redeem(sc.Value, "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	c.ResetSetup()
	if n := c.Setup(); n.InUse || n.Value == "" || n.Value == sc.Value {
		t.Fatalf("after a reset %+v", n)
	}
}

func TestAConsumedSetupCodeNeverComesBack(t *testing.T) {
	c, _, _ := newCodes(t)
	sc := c.Setup()
	if _, err := c.Redeem(sc.Value, "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	c.ConsumeSetup()
	if st := c.Setup(); st.Value != "" || !st.Consumed {
		t.Fatalf("a consumed code %+v", st)
	}
	c.ResetSetup()
	if st := c.Setup(); st.Value != "" {
		t.Fatal("a reset after the first admin made a new setup code")
	}
}

func TestRecoverAccessCodes(t *testing.T) {
	c, clk, _ := newCodes(t)
	c.ConsumeSetup()
	r := c.BeginRecover()
	if r.Value == "" || !r.Expires.Equal(clk.Now().Add(onetime.RecoverLifetime)) {
		t.Fatalf("recover code %+v", r)
	}
	got, err := c.Redeem(r.Value, "192.0.2.50")
	if err != nil || got.Kind != onetime.KindRecover {
		t.Fatalf("redeem: %+v %v", got, err)
	}
	if _, err := c.Redeem(r.Value, "192.0.2.50"); err == nil {
		t.Fatal("a recover code works twice")
	}
	r2 := c.BeginRecover()
	c.CancelRecover()
	if _, ok := c.Recover(); ok {
		t.Fatal("a cancelled recover code is still live")
	}
	if _, err := c.Redeem(r2.Value, "192.0.2.50"); err == nil {
		t.Fatal("a cancelled recover code works")
	}
	r3 := c.BeginRecover()
	clk.Advance(onetime.RecoverLifetime + time.Second)
	if _, ok := c.Recover(); ok {
		t.Fatal("an expired recover code is still live")
	}
	if _, err := c.Redeem(r3.Value, "192.0.2.50"); err == nil {
		t.Fatal("an expired recover code works")
	}
}
