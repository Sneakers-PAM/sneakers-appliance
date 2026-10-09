// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package elevated_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevated"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit/audittest"
)

type fakeAccessd struct {
	mu     sync.Mutex
	ends   time.Time
	begun  *accessv1.BeginElevatedSessionRequest
	ended  *accessv1.EndElevatedSessionRequest
	refuse error
}

func (f *fakeAccessd) BeginElevatedSession(_ context.Context, r *connect.Request[accessv1.BeginElevatedSessionRequest]) (*connect.Response[accessv1.BeginElevatedSessionResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refuse != nil {
		return nil, f.refuse
	}
	f.begun = r.Msg
	return connect.NewResponse(&accessv1.BeginElevatedSessionResponse{
		Elevation: &osadminv1.Elevation{Id: "E-TEST", Admin: "bob", Minutes: 15},
		Ends:      timestamppb.New(f.ends),
	}), nil
}

func (f *fakeAccessd) EndElevatedSession(_ context.Context, r *connect.Request[accessv1.EndElevatedSessionRequest]) (*connect.Response[accessv1.EndElevatedSessionResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ended = r.Msg
	return connect.NewResponse(&accessv1.EndElevatedSessionResponse{}), nil
}

type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func setup(t *testing.T, ends time.Duration) (*fakeAccessd, *osaudit.Log, *syncBuf, elevated.Options) {
	t.Helper()
	if _, err := os.Stat("/dev/ptmx"); err != nil {
		t.Skip("no /dev/ptmx")
	}
	l, err := osaudit.Open(t.TempDir(), osaudit.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { audittest.CheckTargets(t, l) })
	fa := &fakeAccessd{ends: time.Now().Add(ends)}
	out := &syncBuf{}
	pr, _ := io.Pipe()
	t.Cleanup(func() { _ = pr.Close() })
	return fa, l, out, elevated.Options{Accessd: fa, Ticket: "ticket-1", Admin: "bob", Audit: l, In: pr, Out: out, PID: 99, RCDir: t.TempDir()}
}

// The ticket is used up before the shell starts; the session is
// recorded, its hash goes to accessd with the end, and the recording
// verifies against the audit log.
func TestASessionIsRecordedAndReported(t *testing.T) {
	fa, l, out, o := setup(t, time.Minute)
	o.Shell = []string{"/bin/sh", "-c", "echo hello-from-root"}
	res, err := elevated.Run(context.Background(), context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if res.Reason != "exit" || fa.begun.GetPid() != 99 || fa.begun.GetTicket() != "ticket-1" || fa.begun.GetAdmin() != "bob" {
		t.Fatalf("%+v %v", res, fa.begun)
	}
	if !strings.Contains(out.String(), "hello-from-root") || !strings.Contains(out.String(), "recorded") {
		t.Fatalf("out %q", out.String())
	}
	data, err := os.ReadFile(osaudit.RecordingPath(l.Dir(), "E-TEST"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if fa.ended.GetReason() != "exit" || fa.ended.GetRecordingSha256() != hex.EncodeToString(sum[:]) {
		t.Fatalf("%v", fa.ended)
	}
	if !strings.Contains(string(data), "hello-from-root") {
		t.Fatalf("recording %q", data)
	}
	if err := osaudit.VerifyRecording(data, l, "E-TEST"); err != nil {
		t.Fatal(err)
	}
}

func TestTheTimeBoxEndsTheSession(t *testing.T) {
	fa, _, out, o := setup(t, 1500*time.Millisecond)
	o.Shell = []string{"/bin/sh", "-c", "sleep 30"}
	o.Warnings = []time.Duration{time.Second}
	start := time.Now()
	res, err := elevated.Run(context.Background(), context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if res.Reason != "time-box" || fa.ended.GetReason() != "time-box" || time.Since(start) > 10*time.Second {
		t.Fatalf("%+v after %v", res, time.Since(start))
	}
	if !strings.Contains(out.String(), "1s left") || !strings.Contains(out.String(), "The time is up") {
		t.Fatalf("out %q", out.String())
	}
}

func TestTenMinutesIdleEndsTheSession(t *testing.T) {
	fa, _, out, o := setup(t, time.Hour)
	o.Shell = []string{"/bin/sh", "-c", "sleep 30"}
	o.Idle = 400 * time.Millisecond
	res, err := elevated.Run(context.Background(), context.Background(), o)
	if err != nil || res.Reason != "idle" || fa.ended.GetReason() != "idle" {
		t.Fatalf("%+v %v", res, err)
	}
	if !strings.Contains(out.String(), "No key for") {
		t.Fatalf("out %q", out.String())
	}
}

func TestTypingKeepsTheSessionOpen(t *testing.T) {
	_, _, _, o := setup(t, 1500*time.Millisecond)
	o.Shell = []string{"/bin/sh", "-c", "sleep 30"}
	o.Idle = 600 * time.Millisecond
	pr, pw := io.Pipe()
	o.In = pr
	go func() {
		for range 8 {
			time.Sleep(200 * time.Millisecond)
			_, _ = pw.Write([]byte(" "))
		}
	}()
	res, err := elevated.Run(context.Background(), context.Background(), o)
	if err != nil || res.Reason != "time-box" {
		t.Fatalf("keys every 200 ms keep it past the idle time: %+v %v", res, err)
	}
}

func TestTheClientGoingEndsTheSession(t *testing.T) {
	fa, _, _, o := setup(t, time.Hour)
	o.Shell = []string{"/bin/sh", "-c", "sleep 30"}
	pr, pw := io.Pipe()
	o.In = pr
	time.AfterFunc(300*time.Millisecond, func() { _ = pw.Close() })
	start := time.Now()
	res, err := elevated.Run(context.Background(), context.Background(), o)
	if err != nil || res.Reason != "exit" || fa.ended.GetReason() != "exit" || time.Since(start) > 10*time.Second {
		t.Fatalf("%+v %v after %v", res, err, time.Since(start))
	}
}

func TestATerminateEndsTheSession(t *testing.T) {
	fa, _, _, o := setup(t, time.Hour)
	o.Shell = []string{"/bin/sh", "-c", "sleep 30"}
	term, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)
	res, err := elevated.Run(context.Background(), term, o)
	if err != nil || res.Reason != "terminated" || fa.ended.GetReason() != "terminated" {
		t.Fatalf("%+v %v", res, err)
	}
}

// Without accessd's yes there is no shell: an unavailable accessd, a
// refused ticket or no ticket at all stop here.
func TestNoShellWithoutAccessd(t *testing.T) {
	fa, l, _, o := setup(t, time.Hour)
	o.Shell = []string{"/bin/sh", "-c", "echo should-not-run"}
	fa.refuse = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	_, err := elevated.Run(context.Background(), context.Background(), o)
	if err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("%v", err)
	}
	fa.refuse = connect.NewError(connect.CodeFailedPrecondition, errors.New("ELEV_USED"))
	if _, err := elevated.Run(context.Background(), context.Background(), o); err == nil {
		t.Fatal("a refused ticket got a shell")
	}
	fa.refuse = nil
	o.Ticket = ""
	if _, err := elevated.Run(context.Background(), context.Background(), o); err == nil {
		t.Fatal("no ticket got a shell")
	}
	if _, err := os.Stat(osaudit.RecordingPath(l.Dir(), "E-TEST")); err == nil {
		t.Fatal("a refused session left a recording")
	}
}

// With a product installed the shell starts with KUBECONFIG on k0s's admin
// kubeconfig; without one it says so once instead.
func TestTheShellPointsAtTheInstalledK0s(t *testing.T) {
	_, _, out, o := setup(t, time.Minute)
	o.Product = t.TempDir()
	if err := os.WriteFile(o.Product+"/bundle.json", []byte(`{"version":"0.1.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	o.Kubeconfig = "/var/lib/k0s/pki/admin.conf"
	o.Shell = []string{"/bin/sh", "-c", `echo "kc=[$KUBECONFIG] helm=[$HELM_CACHE_HOME]"`}
	if _, err := elevated.Run(context.Background(), context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "kc=[/var/lib/k0s/pki/admin.conf] helm=[/tmp/helm/cache]") {
		t.Fatalf("out %q", out.String())
	}
	if strings.Contains(out.String(), "No product is installed") {
		t.Fatalf("said no product with one installed: %q", out.String())
	}
}

func TestWithNoProductTheShellSaysSo(t *testing.T) {
	_, _, out, o := setup(t, time.Minute)
	o.Product = t.TempDir()
	o.Shell = []string{"/bin/sh", "-c", `echo "kc=[$KUBECONFIG]"`}
	if _, err := elevated.Run(context.Background(), context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "kc=[]") || strings.Count(out.String(), "No product is installed; kubectl and helm come with it.") != 1 {
		t.Fatalf("out %q", out.String())
	}
}

// The prompt is plain text (the host name, the session's end and the
// directory, nothing the shell runs), the shell's ENV start file defines
// help, and the welcome says so.
func TestTheShellsPromptHelpAndWelcome(t *testing.T) {
	_, _, out, o := setup(t, 30*time.Minute)
	o.RCDir = t.TempDir()
	o.Product = t.TempDir()
	o.Shell = []string{"/bin/sh", "-c", `echo "ps1=[$PS1]"; . "$ENV"; help | head -n 3`}
	if _, err := elevated.Run(context.Background(), context.Background(), o); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, `ps1=[[root@\h until `) || !strings.Contains(got, ` UTC] \w # ]`) {
		t.Fatalf("prompt: %q", got)
	}
	if !strings.Contains(got, "Troubleshooting this box") || !strings.Contains(got, "Type help") {
		t.Fatalf("help or the welcome: %q", got)
	}
	if ents, _ := os.ReadDir(o.RCDir); len(ents) != 0 {
		t.Fatalf("the start file outlived the session: %v", ents)
	}
	p := elevated.PromptFor(time.Date(2026, 10, 9, 18, 45, 0, 0, time.UTC))
	if p != `[root@\h until 18:45 UTC] \w # ` || strings.ContainsAny(p, "$`") {
		t.Fatalf("PromptFor %q", p)
	}
}
