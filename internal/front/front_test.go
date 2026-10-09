// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package front_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
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
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sigbundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/webslots"
)

// fakeAPI is accessd's side: GetStatus for a known cookie, and what the
// front forwarded.
type fakeAPI struct {
	osadminv1connect.UnimplementedStatusServiceHandler
	mu      sync.Mutex
	clients []string
	// phase is what GetPhase answers; empty fails it.
	phase  string
	phases int
}

func (f *fakeAPI) GetPhase(context.Context, *connect.Request[osadminv1.GetPhaseRequest]) (*connect.Response[osadminv1.GetPhaseResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.phases++
	if f.phase == "" {
		return nil, connect.NewError(connect.CodeUnavailable, nil)
	}
	return connect.NewResponse(&osadminv1.GetPhaseResponse{Phase: f.phase}), nil
}

func (f *fakeAPI) setPhase(p string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.phase = p
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
	r := &rig{t: t, api: &fakeAPI{phase: osadmin.PhaseNormal}, statusFile: filepath.Join(t.TempDir(), "status.json")}
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

func (r *rig) page(p string) *http.Response {
	r.t.Helper()
	hc := r.ts.Client()
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := hc.Get(r.ts.URL + p)
	if err != nil {
		r.t.Fatal(err)
	}
	_ = res.Body.Close()
	return res
}

// Before setup is done the front sends every page path, / included, to
// /setup, asking accessd for the phase; once setup is done the pages are
// served and accessd isn't asked again.
func TestBeforeSetupThePagesGoToSetup(t *testing.T) {
	r := newRig(t)
	r.api.setPhase(osadmin.PhaseFirstBoot)
	for _, p := range []string{"/", "/home", "/access"} {
		if res := r.page(p); res.StatusCode != http.StatusFound || res.Header.Get("Location") != osadmin.SetupPath {
			t.Fatalf("%s: %d %q", p, res.StatusCode, res.Header.Get("Location"))
		}
	}
	if res := r.page("/setup"); res.StatusCode != http.StatusOK {
		t.Fatalf("/setup: %d", res.StatusCode)
	}
	r.api.setPhase(osadmin.PhaseNormal)
	if res := r.page("/"); res.StatusCode != http.StatusOK {
		t.Fatalf("after setup: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	r.api.mu.Lock()
	asked := r.api.phases
	r.api.mu.Unlock()
	r.page("/home")
	r.page("/access")
	r.api.mu.Lock()
	defer r.api.mu.Unlock()
	if r.api.phases != asked {
		t.Fatalf("the normal phase is kept: asked %d more times", r.api.phases-asked)
	}
}

// With accessd down the phase isn't known, and the pages are served; they
// say the services are unavailable themselves.
func TestAccessdDownServesThePages(t *testing.T) {
	r := newRig(t)
	r.api.setPhase(osadmin.PhaseFirstBoot)
	r.back.Close()
	if res := r.page("/"); res.StatusCode != http.StatusOK {
		t.Fatalf("%d %q", res.StatusCode, res.Header.Get("Location"))
	}
}

// The pages are swapped in one step: the front serves whatever the live
// set serves, an open page's old assets keep answering, and every API
// answer names the served version so the page can offer a reload.
func TestALiveSwapOfThePagesWithTheVersionOnEveryAnswer(t *testing.T) {
	r := newRig(t)
	live := webslots.NewLive(fstest.MapFS{"index.html": {Data: []byte("<html>0.3.0</html>")}, "assets/old.js": {Data: []byte("old")}}, "0.3.0")
	u, _ := url.Parse(r.back.URL)
	f := front.New(front.Options{Backend: u, Transport: r.back.Client().Transport, Assets: live, WebVersion: live.Version})
	ts := httptest.NewServer(f.Handler())
	t.Cleanup(ts.Close)
	get := func(p string) (string, http.Header) {
		res, err := ts.Client().Get(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		return string(b), res.Header
	}
	if b, _ := get("/updates"); b != "<html>0.3.0</html>" {
		t.Fatalf("before: %q", b)
	}
	res, err := osadminv1connect.NewStatusServiceClient(ts.Client(), ts.URL).GetPhase(context.Background(), connect.NewRequest(&osadminv1.GetPhaseRequest{}))
	if err != nil || res.Header().Get(front.WebVersionHeader) != "0.3.0" {
		t.Fatalf("the API answer names %q (%v)", res.Header().Get(front.WebVersionHeader), err)
	}
	sign := testpki.ECDSA(t)
	key, _ := sigbundle.ParsePublicKey(sign.PublicPEM)
	sl := webslots.Slots{Dir: t.TempDir()}
	if err := sl.Stage(updatepkg.Header{Name: updatepkg.NameWeb, Unit: updatepkg.UnitBaseWeb, Version: "0.3.1", Arch: "amd64", Kind: updatepkg.KindFull, Channel: "production"}, func(dir string) error {
		return writeSignedPages(t, sign, dir, "0.3.1")
	}, key); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sl.Apply(); err != nil {
		t.Fatal(err)
	}
	(&webslots.Watcher{Slots: sl, Key: key, Channel: "production", BaseOS: "0.3.0", Live: live}).Sync()
	if b, _ := get("/updates"); b != "<html>0.3.1</html>" {
		t.Fatalf("after: %q", b)
	}
	if b, _ := get("/assets/old.js"); b != "old" {
		t.Fatalf("an open page's old asset: %q", b)
	}
	res, err = osadminv1connect.NewStatusServiceClient(ts.Client(), ts.URL).GetPhase(context.Background(), connect.NewRequest(&osadminv1.GetPhaseRequest{}))
	if err != nil || res.Header().Get(front.WebVersionHeader) != "0.3.1" {
		t.Fatalf("after the swap the API answer names %q (%v)", res.Header().Get(front.WebVersionHeader), err)
	}
}

func writeSignedPages(t *testing.T, sign testpki.ECKey, dir, version string) error {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, webslots.PagesDir), 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, webslots.PagesDir, "index.html"), []byte("<html>"+version+"</html>"), 0o600); err != nil {
		return err
	}
	m, err := webslots.WriteManifest(filepath.Join(dir, webslots.PagesDir), version, "", nil)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, webslots.ManifestFile), m, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, webslots.SigFile), sign.BlobBundle(t, m), 0o600)
}
