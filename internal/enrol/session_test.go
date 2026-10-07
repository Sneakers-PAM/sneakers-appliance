// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package enrol_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/enrol"
)

// local runs the enrolment service in process, as accessd would for the
// enrol uid.
type local struct {
	svc    *enrol.Service
	onWait func()
}

func (l *local) SubmitEnrolmentCode(_ context.Context, r *connect.Request[accessv1.SubmitEnrolmentCodeRequest]) (*connect.Response[accessv1.SubmitEnrolmentCodeResponse], error) {
	k, err := l.svc.Submit(r.Msg.GetCode(), r.Msg.GetPublicKey(), "192.0.2.50")
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New(codes.Describe(err)))
	}
	return connect.NewResponse(&accessv1.SubmitEnrolmentCodeResponse{Id: k.ID, Admin: l.svc.Get().Admin, Fingerprint: k.Fingerprint}), nil
}

func (l *local) GetEnrolmentKey(_ context.Context, r *connect.Request[accessv1.GetEnrolmentKeyRequest]) (*connect.Response[accessv1.GetEnrolmentKeyResponse], error) {
	if l.onWait != nil {
		l.onWait()
		l.onWait = nil
	}
	k, err := l.svc.Key(r.Msg.GetId())
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New(codes.Describe(err)))
	}
	return connect.NewResponse(&accessv1.GetEnrolmentKeyResponse{Key: &accessv1.EnrolmentKey{Id: k.ID, State: string(k.State)}}), nil
}

func login(t *testing.T) accessapi.Login {
	line, pk := key(t)
	return accessapi.Login{Key: pk, KeyLine: line, Source: "192.0.2.50"}
}

func TestTheEnrolSessionWaitsForTheConsole(t *testing.T) {
	f := newFixture(t)
	if _, err := f.svc.Open("alice"); err != nil {
		t.Fatal(err)
	}
	l := &local{svc: f.svc}
	l.onWait = func() {
		k := f.svc.Get().Keys[0]
		if _, err := f.svc.Accept(k.ID, "yes"); err != nil {
			t.Error(err)
		}
	}
	var out strings.Builder
	err := enrol.RunSession(context.Background(), strings.NewReader("ZZZZ-ZZZZ\nAAAA-BBBB\n"), &out, l, login(t), time.Millisecond)
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	for _, want := range []string{"2 attempts left", "Type yes there", "Key enrolled for alice"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("no %q in %q", want, out.String())
		}
	}
}

func TestTheEnrolSessionStopsWhenRefused(t *testing.T) {
	f := newFixture(t)
	if _, err := f.svc.Open("alice"); err != nil {
		t.Fatal(err)
	}
	l := &local{svc: f.svc}
	l.onWait = func() { _ = f.svc.Reject(f.svc.Get().Keys[0].ID) }
	var out strings.Builder
	err := enrol.RunSession(context.Background(), strings.NewReader("AAAA-BBBB\n"), &out, l, login(t), time.Millisecond)
	if !errors.Is(err, enrol.ErrNotEnrolled) || !strings.Contains(out.String(), "refused") {
		t.Fatalf("%v %q", err, out.String())
	}
}

func TestTheEnrolSessionStopsWhenClosed(t *testing.T) {
	f := newFixture(t)
	l := &local{svc: f.svc}
	var out strings.Builder
	err := enrol.RunSession(context.Background(), strings.NewReader("AAAA-BBBB\nAAAA-BBBB\n"), &out, l, login(t), time.Millisecond)
	if !errors.Is(err, enrol.ErrNotEnrolled) || strings.Count(out.String(), "Enrolment code") != 1 {
		t.Fatalf("%v %q", err, out.String())
	}
}

func TestTheEnrolSessionRefusesACertificate(t *testing.T) {
	_, pk := key(t)
	c := &ssh.Certificate{Key: pk}
	var out strings.Builder
	if err := enrol.RunSession(context.Background(), strings.NewReader(""), &out, &local{}, accessapi.Login{Key: c}, time.Millisecond); !errors.Is(err, enrol.ErrNotEnrolled) {
		t.Fatal(err)
	}
}
