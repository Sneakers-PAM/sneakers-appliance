// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package elevated_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevated"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
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

func certLogin(t *testing.T) accessapi.Login {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pk, _ := ssh.NewPublicKey(pub)
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	ca, _ := ssh.NewSignerFromKey(caPriv)
	c := &ssh.Certificate{Key: pk, Serial: 1, CertType: ssh.UserCert, ValidPrincipals: []string{"elev-E-TEST"}, ValidBefore: ssh.CertTimeInfinity}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return accessapi.Login{Key: c, KeyLine: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(c))), Source: "192.0.2.50"}
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
	fa := &fakeAccessd{ends: time.Now().Add(ends)}
	out := &syncBuf{}
	pr, _ := io.Pipe()
	t.Cleanup(func() { _ = pr.Close() })
	return fa, l, out, elevated.Options{Accessd: fa, Login: certLogin(t), Audit: l, In: pr, Out: out, PID: 99}
}

// The certificate is used up before the shell starts; the session is
// recorded, its hash goes to accessd with the end, and the recording
// verifies against the audit log.
func TestASessionIsRecordedAndReported(t *testing.T) {
	fa, l, out, o := setup(t, time.Minute)
	o.Shell = []string{"/bin/sh", "-c", "echo hello-from-root"}
	res, err := elevated.Run(context.Background(), context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if res.Reason != "exit" || fa.begun.GetPid() != 99 || fa.begun.GetCertificate() != o.Login.KeyLine {
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
	if !strings.Contains(out.String(), "1s left") || !strings.Contains(out.String(), "time is up") {
		t.Fatalf("out %q", out.String())
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
// refused certificate or a login without a certificate all stop here.
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
		t.Fatal("a refused certificate got a shell")
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pk, _ := ssh.NewPublicKey(pub)
	o.Login = accessapi.Login{Key: pk, KeyLine: string(ssh.MarshalAuthorizedKey(pk))}
	if _, err := elevated.Run(context.Background(), context.Background(), o); err == nil {
		t.Fatal("a plain key got a shell")
	}
	if _, err := os.Stat(osaudit.RecordingPath(l.Dir(), "E-TEST")); err == nil {
		t.Fatal("a refused session left a recording")
	}
}
