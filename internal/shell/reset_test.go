// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productinfo"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

type resetAccessd struct {
	fakeAccessd
	resets []*accessv1.ResetProductRequest
}

func (f *resetAccessd) ResetProduct(_ context.Context, r *connect.Request[accessv1.ResetProductRequest]) (*connect.Response[accessv1.ResetProductResponse], error) {
	f.saw(r.Header())
	f.resets = append(f.resets, r.Msg)
	return connect.NewResponse(&accessv1.ResetProductResponse{Result: &osadminv1.ResetProductResponse{
		Product: "sneakers", ProductTitle: "Sneakers", Version: "0.2.0", Namespaces: 3, Objects: 41, BytesRemoved: 3 << 20, StagedVersion: "0.2.0",
	}}), nil
}

// secretTerm is the interactive terminal: it answers each prompt in turn
// and records whether it was read with echo.
type secretTerm struct {
	answers []string
	asked   []string
}

func (s *secretTerm) Read([]byte) (int, error) { return 0, nil }

func (s *secretTerm) next(kind, prompt string) (string, error) {
	s.asked = append(s.asked, kind+" "+prompt)
	a := s.answers[0]
	s.answers = s.answers[1:]
	return a, nil
}

func (s *secretTerm) AskLine(prompt string) (string, error)   { return s.next("line", prompt) }
func (s *secretTerm) AskSecret(prompt string) (string, error) { return s.next("secret", prompt) }

func resetEnv(t *testing.T, f *resetAccessd, in any) (*shell.Env, *bytes.Buffer) {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(accessv1connect.NewAccessServiceHandler(f))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	s := &shell.Services{Session: shell.Session{Admin: "alice", KeyFingerprint: "SHA256:abc", Source: "192.0.2.60"}}
	s.UseAccessd(http.DefaultClient, srv.URL)
	var out bytes.Buffer
	e := &shell.Env{Origin: shell.OriginSSH, Backend: s, Out: &out, Err: &out, Product: sneakers, Role: "owner"}
	switch v := in.(type) {
	case string:
		e.In = strings.NewReader(v)
	case *secretTerm:
		e.In = v
	}
	return e, &out
}

// "<product> reset" reads the name and a new code, each answer from the
// same standard input, sends both to accessd with the login's key, and
// says what went and how to install the product again. The session's
// product commands go with it.
func TestTheResetCommandSendsTheNameAndANewCode(t *testing.T) {
	f := &resetAccessd{}
	e, out := resetEnv(t, f, "sneakers\n123456\n")
	if err := shell.Run(context.Background(), e, "sneakers reset"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(f.resets) != 1 || f.resets[0].GetConfirm() != "sneakers" || f.resets[0].GetTotpCode() != "123456" {
		t.Fatalf("resets %v", f.resets)
	}
	if fp := f.headers[0].Get(accessapi.KeyHeader); fp != "SHA256:abc" {
		t.Fatalf("the call carried the key %q, not the login's", fp)
	}
	for _, want := range []string{"can't be undone", "keeps its admins", "Type sneakers", "Sneakers 0.2.0 is removed: 3 namespaces and 41 objects", "3.0 MiB", "Apply the staged Sneakers 0.2.0"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("no %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out.String(), "123456") {
		t.Fatalf("the code was echoed:\n%s", out)
	}
	if e.Product.Present() {
		t.Fatal("the session still offers the product's commands")
	}
}

// On the interactive terminal the name is a prompt of its own and the code
// is read without echo; neither enters the arrow-key recall.
func TestTheResetCodeIsReadWithoutEcho(t *testing.T) {
	f := &resetAccessd{}
	term := &secretTerm{answers: []string{"box1", "654321"}}
	e, out := resetEnv(t, f, term)
	if err := shell.Run(context.Background(), e, "sneakers reset"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(term.asked) != 2 || !strings.HasPrefix(term.asked[0], "line ") || !strings.HasPrefix(term.asked[1], "secret ") {
		t.Fatalf("asked %v", term.asked)
	}
	if f.resets[0].GetConfirm() != "box1" || f.resets[0].GetTotpCode() != "654321" {
		t.Fatalf("resets %v", f.resets)
	}
}

// Nothing typed sends nothing.
func TestAnUnconfirmedResetSendsNothing(t *testing.T) {
	for _, in := range []string{"", "\n", "sneakers\n\n"} {
		f := &resetAccessd{}
		e, out := resetEnv(t, f, in)
		err := shell.Run(context.Background(), e, "sneakers reset")
		assertCode(t, err, "ACCESS_CONFIRM")
		if len(f.resets) != 0 || !strings.Contains(out.String(), "nothing was removed") {
			t.Fatalf("%q: resets %v\n%s", in, f.resets, out)
		}
	}
}

// The reset is an owner's, over SSH: an admin isn't offered it, the
// console hasn't got it, and with no product there's nothing to reset.
func TestTheResetIsAnOwnersOverSSHOnly(t *testing.T) {
	admin := &shell.Env{Origin: shell.OriginSSH, Backend: &recordingBackend{}, Product: sneakers, Role: "admin"}
	var out bytes.Buffer
	admin.Out, admin.Err, admin.In = &out, &out, strings.NewReader("")
	if err := shell.Run(context.Background(), admin, "help sneakers"); err != nil || strings.Contains(out.String(), "reset") {
		t.Fatalf("an admin's help offers the reset (%v):\n%s", err, out.String())
	}
	if !slices.Contains(shell.NamesFor(shell.OriginSSH, sneakers), "sneakers reset") {
		t.Fatal("SSH doesn't offer sneakers reset")
	}
	if slices.Contains(shell.NamesFor(shell.OriginConsole, sneakers), "sneakers reset") {
		t.Fatal("the console offers sneakers reset")
	}
	b := &recordingBackend{}
	console := &shell.Env{Origin: shell.OriginConsole, Backend: b, Product: sneakers, Out: &out, Err: &out, In: strings.NewReader("sneakers\n1\n")}
	if err := shell.Run(context.Background(), console, "sneakers reset"); err == nil || len(b.calls) != 0 {
		t.Fatalf("the console reset: %v, calls %v", err, b.calls)
	}
	_, _, err := runProduct(t, productinfo.Info{}, "sneakers reset")
	assertCode(t, err, "SHELL_UNKNOWN")
}
