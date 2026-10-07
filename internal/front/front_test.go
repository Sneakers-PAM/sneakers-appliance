// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package front_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/front"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
)

// fakeAPI is accessd's side: GetStatus for a known cookie, and what the
// front forwarded.
type fakeAPI struct {
	osadminv1connect.UnimplementedStatusServiceHandler
	mu      sync.Mutex
	clients []string
}

func (f *fakeAPI) GetStatus(_ context.Context, r *connect.Request[osadminv1.GetStatusRequest]) (*connect.Response[osadminv1.GetStatusResponse], error) {
	f.mu.Lock()
	f.clients = append(f.clients, r.Header().Get(accessapi.ClientHeader))
	f.mu.Unlock()
	if !strings.Contains(r.Header().Get("Cookie"), osadmin.CookieName+"=good") {
		return nil, connect.NewError(connect.CodeUnauthenticated, nil)
	}
	return connect.NewResponse(&osadminv1.GetStatusResponse{Hostname: "box1.sneakers.example.org", Version: "0.1.0"}), nil
}

type rig struct {
	t          *testing.T
	api        *fakeAPI
	back       *httptest.Server
	ts         *httptest.Server
	statusFile string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, api: &fakeAPI{}, statusFile: filepath.Join(t.TempDir(), "status.json")}
	mux := http.NewServeMux()
	mux.Handle(osadminv1connect.NewStatusServiceHandler(r.api))
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(io.Discard, req.Body)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("backend " + req.URL.Path))
	})
	r.back = httptest.NewServer(mux)
	t.Cleanup(r.back.Close)
	u, _ := url.Parse(r.back.URL)
	f := front.New(front.Options{
		Backend:    u,
		Transport:  r.back.Client().Transport,
		Assets:     fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html>admin</html>")}},
		StatusFile: r.statusFile,
	})
	r.ts = httptest.NewServer(f.Handler())
	t.Cleanup(r.ts.Close)
	return r
}

func (r *rig) status(cookie string, opts ...connect.ClientOption) (*osadminv1.GetStatusResponse, error) {
	req := connect.NewRequest(&osadminv1.GetStatusRequest{})
	if cookie != "" {
		req.Header().Set("Cookie", osadmin.CookieName+"="+cookie)
	}
	req.Header().Set(accessapi.ClientHeader, "198.51.100.66")
	res, err := osadminv1connect.NewStatusServiceClient(r.ts.Client(), r.ts.URL, opts...).GetStatus(context.Background(), req)
	if err != nil {
		return nil, err
	}
	return res.Msg, nil
}

// The front forwards the API with the browser's own address; a forged
// address header is replaced.
func TestTheAPIGoesToAccessdWithTheBrowsersAddress(t *testing.T) {
	r := newRig(t)
	st, err := r.status("good")
	if err != nil || st.GetHostname() != "box1.sneakers.example.org" {
		t.Fatalf("%v %v", st, err)
	}
	r.api.mu.Lock()
	got := r.api.clients
	r.api.mu.Unlock()
	if len(got) != 1 || got[0] != "127.0.0.1" {
		t.Fatalf("forwarded %v", got)
	}
	for _, p := range []string{"/upload", "/export/audit-log"} {
		res, err := r.ts.Client().Post(r.ts.URL+p, "application/octet-stream", strings.NewReader("x"))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if string(b) != "backend "+p {
			t.Fatalf("%s: %q", p, b)
		}
	}
}

// The pages are the front's own, with :8443's headers; LocalService is
// never forwarded (it's the shell's and the console's).
func TestPagesAndHeaders(t *testing.T) {
	r := newRig(t)
	res, err := r.ts.Client().Get(r.ts.URL + "/access")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if !strings.Contains(string(b), "admin") || !strings.Contains(res.Header.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatalf("%q %v", b, res.Header)
	}
	_, err = osadminv1connect.NewLocalServiceClient(r.ts.Client(), r.ts.URL).ApproveSignIn(context.Background(), connect.NewRequest(&osadminv1.ApproveSignInRequest{Code: "X"}))
	if connect.CodeOf(err) != connect.CodeUnimplemented && connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("LocalService was forwarded: %v", err)
	}
}

// With accessd down every call says the appliance services are
// unavailable, except Status for a browser accessd had signed in, which
// gets the last status it saw, marked as cached.
func TestAccessdDown(t *testing.T) {
	r := newRig(t)
	if _, err := r.status("good"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.status("good", connect.WithProtoJSON()); err != nil {
		t.Fatal(err)
	}
	r.back.Close()
	for _, opts := range [][]connect.ClientOption{nil, {connect.WithProtoJSON()}} {
		st, err := r.status("good", opts...)
		if err != nil {
			t.Fatal(err)
		}
		if st.GetHostname() != "box1.sneakers.example.org" || !accessdDown(st) {
			t.Fatalf("%v", st)
		}
	}
	if _, err := r.status("other"); connect.CodeOf(err) != connect.CodeUnavailable || !strings.Contains(err.Error(), accessapi.Unavailable) {
		t.Fatalf("an unknown browser: %v", err)
	}
	_, err := osadminv1connect.NewAccessServiceClient(r.ts.Client(), r.ts.URL).ListAdmins(context.Background(), connect.NewRequest(&osadminv1.ListAdminsRequest{}))
	if connect.CodeOf(err) != connect.CodeUnavailable || !strings.Contains(err.Error(), accessapi.Unavailable) {
		t.Fatalf("%v", err)
	}
	res, err := r.ts.Client().Post(r.ts.URL+"/upload", "application/octet-stream", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(b), accessapi.Unavailable) {
		t.Fatalf("%d %q", res.StatusCode, b)
	}
}

// A front that has seen no status (it restarted) shows the one accessd
// kept on disk, still only to a browser accessd accepted.
func TestAccessdDownUsesTheStatusFile(t *testing.T) {
	r := newRig(t)
	if err := accessapi.WriteStatusCache(r.statusFile, &osadminv1.GetStatusResponse{Hostname: "from-disk"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	up, err := http.NewRequest(http.MethodPost, r.ts.URL+"/upload", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	up.Header.Set("Cookie", osadmin.CookieName+"=good")
	res, err := r.ts.Client().Do(up)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	r.back.Close()
	if _, err := r.status("other"); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("a browser accessd never accepted got a status: %v", err)
	}
	st, err := r.status("good")
	if err != nil || st.GetHostname() != "from-disk" || !accessdDown(st) {
		t.Fatalf("%v %v", st, err)
	}
}

func accessdDown(st *osadminv1.GetStatusResponse) bool {
	for _, c := range st.GetHealth() {
		if c.GetName() == "accessd" && !c.GetOk() && strings.Contains(c.GetDetail(), accessapi.Unavailable) {
			return true
		}
	}
	return false
}
