// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package weblogin_test

import (
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/weblogin"
)

func TestSessionTimeouts(t *testing.T) {
	clk := clock.NewFake()
	s := weblogin.NewSessions(clk)
	a := s.Create("alice", "192.0.2.50", "ua")
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
	b := s.Create("alice", "192.0.2.50", "ua")
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
	a := s.Create("alice", "192.0.2.50", "ua")
	if !s.Fresh(a) {
		t.Fatal("a new sign-in is fresh")
	}
	clk.Advance(weblogin.StepUpAge + time.Second)
	got, _ := s.Get(a.ID)
	if s.Fresh(got) {
		t.Fatal("older than 5 minutes")
	}
	up, ok := s.StepUp(a.ID)
	if !ok || !s.Fresh(up) || !up.StepUpUntil().Equal(clk.Now().Add(weblogin.StepUpAge)) {
		t.Fatalf("a fresh TOTP code makes the session fresh again: %+v", up)
	}
	if _, ok := s.StepUp("no such session"); ok {
		t.Fatal("a step-up of no session")
	}
}

func TestAtMostFivePerAdmin(t *testing.T) {
	clk := clock.NewFake()
	s := weblogin.NewSessions(clk)
	first := s.Create("alice", "192.0.2.50", "ua")
	for range weblogin.MaxPerAdmin {
		clk.Advance(time.Second)
		s.Create("alice", "192.0.2.50", "ua")
	}
	if _, ok := s.Get(first.ID); ok {
		t.Fatal("the oldest session should be ended")
	}
	if n := len(s.Of("alice")); n != weblogin.MaxPerAdmin {
		t.Fatalf("%d sessions", n)
	}
	s.Create("bob", "192.0.2.51", "ua")
	if len(s.Of("bob")) != 1 {
		t.Fatal("per admin")
	}
}

func TestEndWhere(t *testing.T) {
	s := weblogin.NewSessions(clock.NewFake())
	a := s.Create("alice", "192.0.2.50", "ua")
	b := s.Create("alice", "192.0.2.51", "ua")
	if n := s.EndWhere(func(x weblogin.Session) bool { return x.Source == "192.0.2.50" }); n != 1 {
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
	a := s.Create("alice", "192.0.2.50", "ua")
	b := s.Create("alice", "192.0.2.50", "ua")
	if a.ID == b.ID || a.CSRF == b.CSRF || a.ID == a.CSRF || len(a.ID) < 40 {
		t.Fatal("secrets")
	}
}
