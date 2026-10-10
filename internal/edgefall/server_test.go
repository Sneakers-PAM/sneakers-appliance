// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package edgefall_test

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxstate"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/edgefall"
)

func serve(t *testing.T, s boxstate.State) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(nil)
	ts.Config = edgefall.HTTPServer(edgefall.NewServer(func() boxstate.State { return s }))
	ts.Start()
	t.Cleanup(ts.Close)
	return ts
}

func get(t *testing.T, url string) (*http.Response, string) {
	t.Helper()
	res, err := http.Get(url) // #nosec G107 -- the test server
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return res, string(b)
}

func TestTheStateEndpointSaysTheState(t *testing.T) {
	for _, s := range boxstate.All {
		res, body := get(t, serve(t, s).URL+"/_box/state")
		var got struct {
			State string `json:"state"`
		}
		if err := json.Unmarshal([]byte(body), &got); err != nil || res.StatusCode != http.StatusOK || got.State != string(s) {
			t.Fatalf("%s: %d %q %v", s, res.StatusCode, body, err)
		}
		if !strings.HasPrefix(res.Header.Get("Content-Type"), "application/json") || res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: headers %v", s, res.Header)
		}
	}
}

func TestThePollerIsServed(t *testing.T) {
	res, body := get(t, serve(t, boxstate.Running).URL+"/_box/poll.js")
	if res.StatusCode != http.StatusOK || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/javascript") || !strings.Contains(body, "/_box/state") {
		t.Fatalf("%d %v", res.StatusCode, res.Header)
	}
}

// The page says what the box is doing, as the console's state page does,
// answers 503 with Retry-After, and loads the poller so it reloads itself.
func TestThePageSaysWhatTheBoxIsDoing(t *testing.T) {
	for s, want := range map[boxstate.State]string{
		boxstate.Starting:     "Sneakers-PAM is starting",
		boxstate.Running:      "Sneakers-PAM is starting",
		boxstate.Rebooting:    "Sneakers-PAM is rebooting",
		boxstate.ShuttingDown: "Sneakers-PAM is shutting down",
		boxstate.Updating:     "Sneakers-PAM is updating",
		boxstate.Maintenance:  "Sneakers-PAM is in maintenance",
	} {
		res, body := get(t, serve(t, s).URL+"/")
		if res.StatusCode != http.StatusServiceUnavailable || res.Header.Get("Retry-After") == "" || res.Header.Get(edgefall.StateHeader) != string(s) {
			t.Fatalf("%s: %d %v", s, res.StatusCode, res.Header)
		}
		if !strings.Contains(body, want) || !strings.Contains(body, `src="/_box/poll.js"`) {
			t.Fatalf("%s: %s", s, body)
		}
		csp := res.Header.Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {
			t.Fatalf("%s: CSP %q", s, csp)
		}
	}
}

// edgefall never serves product content and never proxies: every path
// and method but the state endpoint and the poller gets the page and a
// 503, whatever the request names, and nothing behind it is ever asked.
func TestEveryOtherRequestGetsThePageNeverAProxy(t *testing.T) {
	var hits atomic.Int32
	behind := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "product content")
	}))
	defer behind.Close()
	ts := serve(t, boxstate.Rebooting)
	host := strings.TrimPrefix(ts.URL, "http://")
	behindHost := strings.TrimPrefix(behind.URL, "http://")
	for _, req := range []string{
		"GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n",
		"GET /login?next=/secrets HTTP/1.1\r\nHost: " + host + "\r\n\r\n",
		"GET /api/v1/secrets HTTP/1.1\r\nHost: " + behindHost + "\r\n\r\n",
		"GET " + behind.URL + "/ HTTP/1.1\r\nHost: " + behindHost + "\r\n\r\n",
		"GET /_box/../etc/passwd HTTP/1.1\r\nHost: " + host + "\r\n\r\n",
		"GET /_box/state/../../x HTTP/1.1\r\nHost: " + host + "\r\n\r\n",
		"GET /_box/ HTTP/1.1\r\nHost: " + host + "\r\n\r\n",
		"GET /_box/page HTTP/1.1\r\nHost: " + host + "\r\n\r\n",
		"GET /.well-known/acme-challenge/x HTTP/1.1\r\nHost: " + host + "\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 2\r\n\r\n{}",
		"POST /_box/state HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 0\r\n\r\n",
		"PUT /_box/poll.js HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 0\r\n\r\n",
		"DELETE /x HTTP/1.1\r\nHost: " + host + "\r\n\r\n",
		"OPTIONS * HTTP/1.1\r\nHost: " + host + "\r\n\r\n",
		"CONNECT " + behindHost + " HTTP/1.1\r\nHost: " + behindHost + "\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
	} {
		c, err := net.Dial("tcp", host)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(c, req); err != nil {
			t.Fatal(err)
		}
		res, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatalf("%q: %v", req, err)
		}
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		_ = c.Close()
		if res.StatusCode != http.StatusServiceUnavailable && res.StatusCode != http.StatusBadRequest {
			t.Fatalf("%q: %d", req, res.StatusCode)
		}
		if strings.Contains(string(body), "product content") {
			t.Fatalf("%q: served product content", req)
		}
		if res.StatusCode == http.StatusServiceUnavailable && !strings.Contains(string(body), "Sneakers-PAM is rebooting") {
			t.Fatalf("%q: %s", req, body)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the server behind was asked %d times", n)
	}
}

// Port 80 sends everyone to https, as Traefik's 80 does.
func TestPlainHTTPRedirectsToHTTPS(t *testing.T) {
	ts := httptest.NewServer(edgefall.Redirect())
	defer ts.Close()
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/hello?x=1", nil)
	req.Host = "box.example.org"
	res, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusMovedPermanently || res.Header.Get("Location") != "https://box.example.org/hello?x=1" {
		t.Fatalf("%d %q", res.StatusCode, res.Header.Get("Location"))
	}
	req.Host = "bad host\r\nx"
	res, err = hc.Do(req)
	if err == nil {
		_ = res.Body.Close()
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("a bad host got %d", res.StatusCode)
		}
	}
}

// The poller lays the same words over a product page as the page shows,
// for every state.
func TestThePollerAndThePageSayTheSame(t *testing.T) {
	_, js := get(t, serve(t, boxstate.Running).URL+"/_box/poll.js")
	for _, s := range boxstate.All {
		if s == boxstate.Running {
			continue
		}
		w := edgefall.WordsFor(s)
		key := string(s)
		if strings.Contains(key, "-") {
			key = `"` + key + `"`
		}
		line := key + `: [` + strconv.Quote(w.Title) + `, ` + strconv.Quote(w.Note) + `]`
		if !strings.Contains(js, line) {
			t.Errorf("poll.js lacks %s", line)
		}
	}
}

// The page's only style is the inline stylesheet the CSP's hash allows.
func TestThePagesStyleIsTheOneTheCSPAllows(t *testing.T) {
	res, body := get(t, serve(t, boxstate.Rebooting).URL+"/")
	_, rest, ok := strings.Cut(body, "<style>")
	css, _, ok2 := strings.Cut(rest, "</style>")
	if !ok || !ok2 || strings.Count(body, "<style") != 1 || strings.Contains(body, "style=") {
		t.Fatalf("the page's styles: %s", body)
	}
	sum := sha256.Sum256([]byte(css))
	if want := "style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"; !strings.Contains(res.Header.Get("Content-Security-Policy"), want) {
		t.Fatalf("CSP %q lacks %q", res.Header.Get("Content-Security-Policy"), want)
	}
}

// The handoff is a POST on the loopback listener only; anything else
// there is edgefall as before.
func TestTheLocalHandlerTakesTheEdgesHandoff(t *testing.T) {
	asked := 0
	h := edgefall.LocalHandler(edgefall.NewServer(func() boxstate.State { return boxstate.Starting }), func() bool { asked++; return true })
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, edgefall.HandoffPath, nil))
	if rec.Code != http.StatusNoContent || asked != 1 {
		t.Fatalf("POST: %d, asked %d", rec.Code, asked)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, edgefall.HandoffPath, nil))
	if rec.Code != http.StatusServiceUnavailable || asked != 1 {
		t.Fatalf("GET: %d, asked %d", rec.Code, asked)
	}
	rec = httptest.NewRecorder()
	edgefall.NewServer(func() boxstate.State { return boxstate.Starting }).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, edgefall.HandoffPath, nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("the 443 handler took a handoff: %d", rec.Code)
	}
}

func gate(t *testing.T, s boxstate.State, uri, from string) *httptest.ResponseRecorder {
	t.Helper()
	h := edgefall.LocalHandler(edgefall.NewServer(func() boxstate.State { return s }), func() bool { return false })
	req := httptest.NewRequest(http.MethodGet, edgefall.GatePath, nil)
	req.Header.Set("X-Forwarded-Uri", uri)
	req.Header.Set("X-Forwarded-Method", http.MethodGet)
	req.Header.Set("X-Forwarded-For", from)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// The gate is the edge's forward check for every request on 443: it lets
// the request through only while the box is running (the product ready),
// and answers the branded page with 503 and the state otherwise, so no one
// signs in to, and no agent writes to, a product that isn't ready.
func TestTheGateHoldsProductRequestsUntilTheBoxRuns(t *testing.T) {
	for _, s := range boxstate.All {
		for _, uri := range []string{"/", "/sign-in", "/secret/s-1", "/graphql", "/mcp", "/oauth/oauth2/token"} {
			rec := gate(t, s, uri, "192.0.2.10")
			if s == boxstate.Running {
				if rec.Code != http.StatusNoContent {
					t.Fatalf("%s %s: %d", s, uri, rec.Code)
				}
				continue
			}
			if rec.Code != http.StatusServiceUnavailable || rec.Header().Get(edgefall.StateHeader) != string(s) || rec.Header().Get("Retry-After") == "" {
				t.Fatalf("%s %s: %d %v", s, uri, rec.Code, rec.Header())
			}
			if !strings.Contains(rec.Body.String(), edgefall.WordsFor(s).Title) || !strings.Contains(rec.Body.String(), "/_box/poll.js") {
				t.Fatalf("%s %s: the page doesn't say what the box is doing", s, uri)
			}
		}
	}
}

// The poller's own paths always pass, so an open tab learns the state
// through the same origin, and so does the box itself on loopback: its
// readiness check asks the product through the edge before the gate
// opens.
func TestTheGateLetsThePollerAndTheBoxThrough(t *testing.T) {
	for _, uri := range []string{"/_box/state", "/_box/poll.js", "/_box/logo"} {
		if rec := gate(t, boxstate.Updating, uri, "192.0.2.10"); rec.Code != http.StatusNoContent {
			t.Fatalf("%s: %d", uri, rec.Code)
		}
	}
	for _, from := range []string{"127.0.0.1", "::1", "192.0.2.10, 127.0.0.1"} {
		if rec := gate(t, boxstate.Starting, "/", from); rec.Code != http.StatusNoContent {
			t.Fatalf("from %q: %d", from, rec.Code)
		}
	}
	for _, c := range []struct{ uri, from string }{
		{"/_box/../secret/s-1", "192.0.2.10"},
		{"/_box/%2e%2e/secret/s-1", "192.0.2.10"},
		{"/_boxes", "192.0.2.10"},
		{"/", "127.0.0.1, 192.0.2.10"},
		{"/", ""},
	} {
		if rec := gate(t, boxstate.Starting, c.uri, c.from); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%q from %q: %d", c.uri, c.from, rec.Code)
		}
	}
}

// The gate is on the loopback listener only: on 443 edgefall itself
// answers the page for it, as for any path.
func TestTheGateIsNotOn443(t *testing.T) {
	rec := httptest.NewRecorder()
	edgefall.NewServer(func() boxstate.State { return boxstate.Running }).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, edgefall.GatePath, nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("443 answered the gate: %d", rec.Code)
	}
}
