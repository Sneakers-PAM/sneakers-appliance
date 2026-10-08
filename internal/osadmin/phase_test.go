// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
)

func (b *box) finishSetup() {
	b.t.Helper()
	if err := os.WriteFile(filepath.Join(b.state, "setup", osadmin.DoneMarker), nil, 0o600); err != nil {
		b.t.Fatal(err)
	}
	b.done = true
}

// Anyone may ask the phase: the pages read it before a session exists.
func TestThePhaseIsPublic(t *testing.T) {
	b := newBox(t, false)
	st := osadminv1connect.NewStatusServiceClient(b.browser().hc, b.ts.URL)
	ctx := context.Background()
	p, err := st.GetPhase(ctx, connect.NewRequest(&osadminv1.GetPhaseRequest{}))
	if err != nil || p.Msg.GetPhase() != osadmin.PhaseFirstBoot {
		t.Fatalf("before setup: %v %v", p, err)
	}
	b.finishSetup()
	p, err = st.GetPhase(ctx, connect.NewRequest(&osadminv1.GetPhaseRequest{}))
	if err != nil || p.Msg.GetPhase() != osadmin.PhaseNormal {
		t.Fatalf("after setup: %v %v", p, err)
	}
}

var pageAssets = fstest.MapFS{
	"index.html":       &fstest.MapFile{Data: []byte("<html>admin</html>")},
	"assets/app.js":    &fstest.MapFile{Data: []byte("console.log(1)")},
	"assets/app.css":   &fstest.MapFile{Data: []byte("body{}")},
	"favicon.svg":      &fstest.MapFile{Data: []byte("<svg/>")},
	"assets/fonts/a.w": &fstest.MapFile{Data: []byte("w")},
}

func get(t *testing.T, h http.Handler, method, p string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, p, nil))
	return w
}

// Before setup is done every page path, the sign-in page at / included,
// goes to /setup; the stepper and the files the pages load are served.
func TestBeforeSetupEveryPageGoesToSetup(t *testing.T) {
	h := osadmin.PagesHandler(pageAssets, func(*http.Request) (string, error) { return osadmin.PhaseFirstBoot, nil }, nil)
	for _, p := range []string{"/", "/home", "/updates", "/access?x=1", "/index.html", "/assets", "/assets/", "/no-such-page", "/setupx"} {
		for _, m := range []string{http.MethodGet, http.MethodHead} {
			w := get(t, h, m, p)
			if w.Code != http.StatusFound || w.Header().Get("Location") != osadmin.SetupPath {
				t.Errorf("%s %s: %d %q", m, p, w.Code, w.Header().Get("Location"))
			}
		}
	}
	for _, p := range []string{"/setup", "/setup/", "/assets/app.js", "/assets/app.css", "/favicon.svg", "/assets/fonts/a.w"} {
		if w := get(t, h, http.MethodGet, p); w.Code != http.StatusOK {
			t.Errorf("GET %s: %d %q", p, w.Code, w.Header().Get("Location"))
		}
	}
	if w := get(t, h, http.MethodGet, "/setup"); w.Body.String() != "<html>admin</html>" {
		t.Errorf("/setup is the pages' index: %q", w.Body.String())
	}
}

func TestAfterSetupThePagesAreServed(t *testing.T) {
	h := osadmin.PagesHandler(pageAssets, func(*http.Request) (string, error) { return osadmin.PhaseNormal, nil }, nil)
	for _, p := range []string{"/", "/home", "/setup", "/assets/app.js"} {
		if w := get(t, h, http.MethodGet, p); w.Code != http.StatusOK {
			t.Errorf("GET %s: %d %q", p, w.Code, w.Header().Get("Location"))
		}
	}
}

// When the phase can't be read the pages are served as they are: the
// pages and the API still refuse what the phase doesn't allow.
func TestAnUnknownPhaseServesThePages(t *testing.T) {
	h := osadmin.PagesHandler(pageAssets, func(*http.Request) (string, error) { return "", errors.New("accessd is down") }, nil)
	if w := get(t, h, http.MethodGet, "/"); w.Code != http.StatusOK {
		t.Fatalf("%d %q", w.Code, w.Header().Get("Location"))
	}
}

// The one-process handler gates its pages on the box's own phase.
func TestTheServerSendsPagesToSetupUntilItIsDone(t *testing.T) {
	b := newBox(t, false, func(_ *box, o *osadmin.Options) { o.Assets = pageAssets })
	hc := b.ts.Client()
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := hc.Get(b.ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != osadmin.SetupPath {
		t.Fatalf("before setup: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	b.finishSetup()
	res, err = hc.Get(b.ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("after setup: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
}
