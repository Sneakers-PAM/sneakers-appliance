// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package weblogin_test

import (
	"regexp"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/weblogin"
)

const fp = "SHA256:aliceKey"

func begin(t *testing.T, m *weblogin.Manager) weblogin.Code {
	t.Helper()
	c, err := m.Begin("192.0.2.50", "Firefox")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCodeShape(t *testing.T) {
	m := weblogin.New(clock.NewFake())
	c := begin(t, m)
	if !regexp.MustCompile(`^[A-Z2-9]{4}-[A-Z2-9]{4}$`).MatchString(c.Code) {
		t.Fatalf("code %q", c.Code)
	}
	if c.PollToken == "" || c.PollToken == c.Code {
		t.Fatal("poll token")
	}
	d, err := m.Describe(c.Code)
	if err != nil || d.Source != "192.0.2.50" || d.UserAgent != "Firefox" {
		t.Fatalf("%+v %v", d, err)
	}
}

func TestApproveThenPollOnce(t *testing.T) {
	m := weblogin.New(clock.NewFake())
	c := begin(t, m)
	if st, _ := m.Poll(c.PollToken); st != weblogin.Pending {
		t.Fatalf("state %v", st)
	}
	if err := m.Approve(c.Code, "alice", fp); err != nil {
		t.Fatal(err)
	}
	st, ap := m.Poll(c.PollToken)
	if st != weblogin.Approved || ap.Admin != "alice" || ap.KeyFP != fp || ap.Source != "192.0.2.50" {
		t.Fatalf("%v %+v", st, ap)
	}
	if st, _ := m.Poll(c.PollToken); st != weblogin.Expired {
		t.Fatal("a code works once")
	}
	if err := m.Approve(c.Code, "alice", fp); !codes.Is(err, codes.LoginCode) {
		t.Fatalf("second approval: %v", err)
	}
}

func TestApproveAcceptsLowerCaseWithoutDash(t *testing.T) {
	m := weblogin.New(clock.NewFake())
	c := begin(t, m)
	raw := c.Code[:4] + c.Code[5:]
	if err := m.Approve(" "+lower(raw)+" ", "alice", fp); err != nil {
		t.Fatal(err)
	}
}

func lower(s string) string {
	b := []byte(s)
	for i, ch := range b {
		if ch >= 'A' && ch <= 'Z' {
			b[i] = ch + 32
		}
	}
	return string(b)
}

func TestCodeExpiresAfterFiveMinutes(t *testing.T) {
	clk := clock.NewFake()
	m := weblogin.New(clk)
	c := begin(t, m)
	clk.Advance(weblogin.CodeLifetime + time.Second)
	if err := m.Approve(c.Code, "alice", fp); !codes.Is(err, codes.LoginCode) {
		t.Fatalf("expired: %v", err)
	}
	if _, err := m.Describe(c.Code); !codes.Is(err, codes.LoginCode) {
		t.Fatal("describe expired")
	}
	if st, _ := m.Poll(c.PollToken); st != weblogin.Expired {
		t.Fatal("poll expired")
	}
}

func TestUnknownCode(t *testing.T) {
	m := weblogin.New(clock.NewFake())
	if err := m.Approve("ABCD-EFGH", "alice", fp); !codes.Is(err, codes.LoginCode) {
		t.Fatal(err)
	}
}

func TestPendingCodesAreCapped(t *testing.T) {
	m := weblogin.New(clock.NewFake())
	for range weblogin.MaxPending {
		begin(t, m)
	}
	if _, err := m.Begin("192.0.2.51", "x"); !codes.Is(err, codes.LoginCode) {
		t.Fatalf("over the cap: %v", err)
	}
}

func TestSessionTimeouts(t *testing.T) {
	clk := clock.NewFake()
	s := weblogin.NewSessions(clk)
	a := s.Create("alice", fp, "192.0.2.50", "ua")
	clk.Advance(weblogin.IdleTimeout - time.Minute)
	if _, ok := s.Get(a.ID); !ok {
		t.Fatal("active session")
	}
	clk.Advance(weblogin.IdleTimeout - time.Minute)
	if _, ok := s.Get(a.ID); !ok {
		t.Fatal("each call moves the idle timeout")
	}
	clk.Advance(weblogin.IdleTimeout + time.Second)
	if _, ok := s.Get(a.ID); ok {
		t.Fatal("idle session should end")
	}
	b := s.Create("alice", fp, "192.0.2.50", "ua")
	for range 40 {
		clk.Advance(14 * time.Minute)
		if _, ok := s.Get(b.ID); !ok {
			break
		}
	}
	if _, ok := s.Get(b.ID); ok {
		t.Fatal("the absolute limit ends a busy session")
	}
}

func TestStepUp(t *testing.T) {
	clk := clock.NewFake()
	s := weblogin.NewSessions(clk)
	a := s.Create("alice", fp, "192.0.2.50", "ua")
	if !s.Fresh(a) {
		t.Fatal("a new sign-in is fresh")
	}
	clk.Advance(weblogin.StepUpAge + time.Second)
	got, _ := s.Get(a.ID)
	if s.Fresh(got) {
		t.Fatal("older than 5 minutes")
	}
}

func TestAtMostFivePerAdmin(t *testing.T) {
	clk := clock.NewFake()
	s := weblogin.NewSessions(clk)
	first := s.Create("alice", fp, "192.0.2.50", "ua")
	for range weblogin.MaxPerAdmin {
		clk.Advance(time.Second)
		s.Create("alice", fp, "192.0.2.50", "ua")
	}
	if _, ok := s.Get(first.ID); ok {
		t.Fatal("the oldest session should be ended")
	}
	if n := len(s.Of("alice")); n != weblogin.MaxPerAdmin {
		t.Fatalf("%d sessions", n)
	}
	s.Create("bob", "SHA256:bob", "192.0.2.51", "ua")
	if len(s.Of("bob")) != 1 {
		t.Fatal("per admin")
	}
}

func TestEndWhere(t *testing.T) {
	s := weblogin.NewSessions(clock.NewFake())
	a := s.Create("alice", fp, "192.0.2.50", "ua")
	b := s.Create("alice", "SHA256:other", "192.0.2.50", "ua")
	if n := s.EndWhere(func(x weblogin.Session) bool { return x.KeyFP == fp }); n != 1 {
		t.Fatalf("ended %d", n)
	}
	if _, ok := s.Get(a.ID); ok {
		t.Fatal("a")
	}
	if _, ok := s.Get(b.ID); !ok {
		t.Fatal("b")
	}
	s.End(b.ID)
	if _, ok := s.Get(b.ID); ok {
		t.Fatal("end")
	}
}

func TestSessionSecretsAreDistinct(t *testing.T) {
	s := weblogin.NewSessions(clock.NewFake())
	a := s.Create("alice", fp, "192.0.2.50", "ua")
	b := s.Create("alice", fp, "192.0.2.50", "ua")
	if a.ID == b.ID || a.CSRF == b.CSRF || a.ID == a.CSRF || len(a.ID) < 40 {
		t.Fatal("secrets")
	}
}
