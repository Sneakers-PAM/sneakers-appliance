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
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

type valueAccessd struct {
	fakeAccessd
	answer *osadminv1.GetExposedValueResponse
	asked  []string
}

func (f *valueAccessd) GetExposedValue(_ context.Context, r *connect.Request[accessv1.GetExposedValueRequest]) (*connect.Response[accessv1.GetExposedValueResponse], error) {
	f.saw(r.Header())
	f.asked = append(f.asked, r.Msg.GetName())
	return connect.NewResponse(&accessv1.GetExposedValueResponse{Value: f.answer}), nil
}

var spec = productspec.Spec{Format: 2, ExposedValues: []productspec.ExposedValue{
	{Name: "setup-token", Secret: "sneakers/sneakers-setup-token", Key: "SETUP_TOKEN", Roles: []string{"owner", "admin"}, Label: "Sneakers setup token"},
	{Name: "support-id", Secret: "sneakers/sneakers-support", Key: "SUPPORT_ID", Roles: []string{"owner"}},
}}

// The values a product exposes are its own commands, "<product> <name>",
// offered only to the roles the bundle lists; each one asks accessd.
func TestAProductsExposedValuesAreItsCommands(t *testing.T) {
	admin := shell.ValuesFor(spec, "admin")
	names := shell.NamesFor(shell.OriginSSH, sneakers, admin...)
	if !slices.Contains(names, "sneakers setup-token") || slices.Contains(names, "sneakers support-id") {
		t.Fatalf("an admin's names %v", names)
	}
	owner := shell.ValuesFor(spec, "owner")
	if !slices.Contains(shell.NamesFor(shell.OriginSSH, sneakers, owner...), "sneakers support-id") {
		t.Fatal("an owner isn't offered support-id")
	}
	if got := shell.CompleteFor(shell.OriginSSH, sneakers, "sneakers s", admin...); got != "sneakers setup-token " {
		t.Fatalf("completes %q", got)
	}
	if slices.Contains(shell.NamesFor(shell.OriginConsole, sneakers, owner...), "sneakers setup-token") {
		t.Fatal("the console offers a product value")
	}

	f := &valueAccessd{answer: &osadminv1.GetExposedValueResponse{ProductTitle: "Sneakers", Value: "stp_value",
		Entry: &osadminv1.ExposedValue{Name: "setup-token", Label: "Sneakers setup token", OneTime: true, Link: "https://box1.sneakers.example.org/admin/setup"}}}
	out, err := runValue(t, f, admin, "sneakers setup-token")
	if err != nil || !strings.Contains(out, "stp_value") || !strings.Contains(out, "https://box1.sneakers.example.org/admin/setup") || !strings.Contains(out, "Sneakers setup token") {
		t.Fatalf("%v\n%s", err, out)
	}
	f.answer = &osadminv1.GetExposedValueResponse{ProductTitle: "Sneakers", Entry: &osadminv1.ExposedValue{Name: "setup-token", Label: "Sneakers setup token", OneTime: true, Consumed: true}}
	out, err = runValue(t, f, admin, "sneakers setup-token")
	if err != nil || !strings.Contains(out, "already used") || strings.Contains(out, "stp_") || strings.Contains(out, "https://") {
		t.Fatalf("after it was used: %v\n%s", err, out)
	}
	if !slices.Equal(f.asked, []string{"setup-token", "setup-token"}) {
		t.Fatalf("accessd was asked %v", f.asked)
	}
	// Nothing undeclared is a command: no generic read reaches accessd.
	for _, line := range []string{"sneakers support-id", "sneakers SETUP_TOKEN", "sneakers setup-token OTHER"} {
		_, _ = runValue(t, f, admin, line)
	}
	_, _ = runValue(t, f, owner, "sneakers sneakers-db")
	if len(f.asked) != 2 {
		t.Fatalf("accessd was asked %v", f.asked)
	}
}

func runValue(t *testing.T, f *valueAccessd, values []shell.Value, line string) (string, error) {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(accessv1connect.NewAccessServiceHandler(f))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	s := &shell.Services{Session: shell.Session{Admin: "alice", KeyFingerprint: "SHA256:abc", Source: "192.0.2.60"}}
	s.UseAccessd(http.DefaultClient, srv.URL)
	var out, errb bytes.Buffer
	e := &shell.Env{Origin: shell.OriginSSH, Backend: s, In: strings.NewReader(""), Out: &out, Err: &errb, Product: sneakers, Values: values}
	err := shell.Run(context.Background(), e, line)
	return out.String() + errb.String(), err
}
