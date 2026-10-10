// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

type updatesAccessd struct {
	fakeAccessd
	status *osadminv1.MirrorStatus
	sets   []*accessv1.SetUpdateChannelRequest
}

func (f *updatesAccessd) GetUpdateChannel(_ context.Context, r *connect.Request[accessv1.GetUpdateChannelRequest]) (*connect.Response[accessv1.GetUpdateChannelResponse], error) {
	f.saw(r.Header())
	return connect.NewResponse(&accessv1.GetUpdateChannelResponse{Policy: &osadminv1.UpgradePolicy{Source: "builtin"}, MirrorStatus: f.status}), nil
}

func (f *updatesAccessd) SetUpdateChannel(_ context.Context, r *connect.Request[accessv1.SetUpdateChannelRequest]) (*connect.Response[accessv1.SetUpdateChannelResponse], error) {
	f.saw(r.Header())
	f.sets = append(f.sets, r.Msg)
	return connect.NewResponse(&accessv1.SetUpdateChannelResponse{}), nil
}

func runUpdates(t *testing.T, f *updatesAccessd, line string) (string, error) {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(accessv1connect.NewAccessServiceHandler(f))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	s := &shell.Services{Session: shell.Session{Admin: "alice", KeyFingerprint: "SHA256:abc", Source: "192.0.2.60"}}
	s.UseAccessd(http.DefaultClient, srv.URL)
	var out, errb bytes.Buffer
	e := &shell.Env{Origin: shell.OriginSSH, Backend: s, In: strings.NewReader(""), Out: &out, Err: &errb}
	err := shell.Run(context.Background(), e, line)
	return out.String() + errb.String(), err
}

// "updates" shows the GitHub source's channel and the release last
// picked; "updates channel" and, on a lab build, "updates repo" set them,
// the same settings as the mirror card on :8443.
func TestTheShellsUpdatesCommandShowsAndSetsTheChannel(t *testing.T) {
	f := &updatesAccessd{status: &osadminv1.MirrorStatus{ReleaseChannel: "rc", ReleaseChannelDefault: true, ReleaseRepo: "Sneakers-PAM/sneakers-appliance", ReleaseTag: "v0.1.0-rc.1"}}
	out, err := runUpdates(t, f, "updates")
	if err != nil || !strings.Contains(out, "rc (the default") || !strings.Contains(out, "Sneakers-PAM/sneakers-appliance") || !strings.Contains(out, "v0.1.0-rc.1") {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := runUpdates(t, f, "updates channel stable"); err != nil {
		t.Fatal(err)
	}
	if _, err := runUpdates(t, f, "updates channel default"); err != nil {
		t.Fatal(err)
	}
	if _, err := runUpdates(t, f, "updates repo example/throwaway"); err != nil {
		t.Fatal(err)
	}
	if _, err := runUpdates(t, f, "updates repo default"); err != nil {
		t.Fatal(err)
	}
	if len(f.sets) != 4 || f.sets[0].GetReleaseChannel() != "stable" || f.sets[0].ReleaseRepo != nil ||
		f.sets[1].ReleaseChannel == nil || f.sets[1].GetReleaseChannel() != "" ||
		f.sets[2].GetReleaseRepo() != "example/throwaway" || f.sets[2].ReleaseChannel != nil ||
		f.sets[3].ReleaseRepo == nil || f.sets[3].GetReleaseRepo() != "" {
		t.Fatalf("sets %v", f.sets)
	}
	for _, line := range []string{"updates channel beta", "updates colour blue", "updates channel", "updates repo"} {
		_, err := runUpdates(t, f, line)
		assertCode(t, err, "SHELL_PARSE")
	}
	if len(f.sets) != 4 {
		t.Fatalf("a bad line set something: %v", f.sets)
	}
}

// Tab completes updates' settings and the channel's values.
func TestTabCompletesTheUpdatesSettings(t *testing.T) {
	for typed, want := range map[string]string{
		"upd":                 "updates ",
		"updates ch":          "updates channel ",
		"updates channel s":   "updates channel stable ",
		"updates channel d":   "updates channel default ",
		"updates r":           "updates repo ",
		"updates repo d":      "updates repo default ",
		"updates channel rc ": "updates channel rc ",
	} {
		if got, _ := completeAs("owner", typed); got != want {
			t.Errorf("%q completes to %q, want %q", typed, got, want)
		}
	}
}
