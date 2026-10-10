// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package edgefall_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxstate"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/edgefall"
)

type event struct {
	State  string  `json:"state"`
	Kind   *string `json:"kind"`
	Step   string  `json:"step"`
	Detail string  `json:"detail"`
	Since  string  `json:"since"`
	Seq    int64   `json:"seq"`
}

// stream reads a text/event-stream: each event's data line, decoded, and
// each comment and retry line as it is.
type stream struct {
	t      *testing.T
	res    *http.Response
	events chan event
	lines  chan string
}

func openStream(t *testing.T, url string) *stream {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	s := &stream{t: t, res: res, events: make(chan event, 32), lines: make(chan string, 64)}
	go func() {
		sc := bufio.NewScanner(res.Body)
		for sc.Scan() {
			line := sc.Text()
			s.lines <- line
			if data, ok := strings.CutPrefix(line, "data: "); ok {
				var e event
				if err := json.Unmarshal([]byte(data), &e); err == nil {
					s.events <- e
				}
			}
		}
	}()
	return s
}

func (s *stream) next() event {
	s.t.Helper()
	select {
	case e := <-s.events:
		return e
	case <-time.After(3 * time.Second):
		s.t.Fatal("no event within 3 seconds")
	}
	return event{}
}

func (s *stream) line(want string) {
	s.t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case l := <-s.lines:
			if l == want {
				return
			}
		case <-deadline:
			s.t.Fatalf("no %q line within 3 seconds", want)
		}
	}
}

func eventsServer(t *testing.T, w *edgefall.Watcher) *httptest.Server {
	t.Helper()
	h := edgefall.NewServer(w.State)
	h.SetEvents(w.Events())
	ts := httptest.NewUnstartedServer(nil)
	ts.Config = edgefall.HTTPServer(h)
	ts.Start()
	t.Cleanup(ts.Close)
	return ts
}

func kind(e event) string {
	if e.Kind == nil {
		return "null"
	}
	return *e.Kind
}

// A client gets the stream's headers, retry once and the current state at
// once, then each change as it happens, with an increasing seq.
func TestTheEventStreamStartsWithTheCurrentState(t *testing.T) {
	w, src, _ := watcher(t)
	src.err = nil
	src.p = edgefall.Phase{ProductInstalled: true, ProductRunning: true, State: "running"}
	w.Poll(context.Background())
	s := openStream(t, eventsServer(t, w).URL+edgefall.EventsPath)
	h := s.res.Header
	if s.res.StatusCode != http.StatusOK || h.Get("Content-Type") != "text/event-stream" || h.Get("Cache-Control") != "no-cache" || h.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("%d %v", s.res.StatusCode, h)
	}
	s.line("retry: 2000")
	first := s.next()
	if first.State != "running" || kind(first) != "null" || first.Seq < 1 {
		t.Fatalf("first %+v", first)
	}
	if _, err := time.Parse(time.RFC3339, first.Since); err != nil {
		t.Fatalf("since %q: %v", first.Since, err)
	}
	src.p = edgefall.Phase{ProductInstalled: true, ProductRunning: true, State: "updating", Kind: "product-apply", Step: "pods", Detail: "Rolling out"}
	w.Poll(context.Background())
	e := s.next()
	if e.State != "updating" || kind(e) != "product-apply" || e.Step != "pods" || e.Detail != "Rolling out" || e.Seq <= first.Seq {
		t.Fatalf("the change %+v after %+v", e, first)
	}
	// The same state again sends nothing new.
	w.Poll(context.Background())
	src.p.Step = "product_health"
	w.Poll(context.Background())
	if e2 := s.next(); e2.Step != "product_health" || e2.Seq != e.Seq+1 {
		t.Fatalf("the next step %+v after %+v", e2, e)
	}
}

// A reboot and a shutdown name their kind; an update without one is an
// update.
func TestTheEventNamesTheKind(t *testing.T) {
	for _, c := range []struct {
		p    edgefall.Phase
		want string
	}{
		{edgefall.Phase{State: "rebooting"}, "reboot"},
		{edgefall.Phase{State: "shutting-down"}, "shutdown"},
		{edgefall.Phase{State: "updating"}, "update"},
		{edgefall.Phase{State: "updating", Kind: "update"}, "update"},
		{edgefall.Phase{State: "updating", Kind: "product-apply"}, "product-apply"},
		{edgefall.Phase{State: "starting", Kind: "product-apply"}, "null"},
	} {
		w, src, _ := watcher(t)
		src.err, src.p = nil, c.p
		w.Poll(context.Background())
		raw, _ := json.Marshal(w.Events().Current())
		var e event
		_ = json.Unmarshal(raw, &e)
		if kind(e) != c.want {
			t.Fatalf("%+v: kind %s, want %s", c.p, kind(e), c.want)
		}
	}
}

// A heartbeat comment keeps an idle stream open through proxies.
func TestTheEventStreamSendsHeartbeats(t *testing.T) {
	defer edgefall.SetHeartbeat(20 * time.Millisecond)()
	w, _, _ := watcher(t)
	s := openStream(t, eventsServer(t, w).URL+edgefall.EventsPath)
	s.next()
	s.line(": hb")
	s.line(": hb")
}

// The stream outlives the listener's write timeout.
func TestTheEventStreamOutlivesTheWriteTimeout(t *testing.T) {
	defer edgefall.SetHeartbeat(20 * time.Millisecond)()
	w, _, _ := watcher(t)
	h := edgefall.NewServer(w.State)
	h.SetEvents(w.Events())
	ts := httptest.NewUnstartedServer(nil)
	ts.Config = edgefall.HTTPServer(h)
	ts.Config.WriteTimeout = 100 * time.Millisecond
	ts.Start()
	t.Cleanup(ts.Close)
	s := openStream(t, ts.URL+edgefall.EventsPath)
	s.next()
	time.Sleep(300 * time.Millisecond)
	s.line(": hb")
}

// Through a reverse proxy, as the edge forwards /_box/ to edgefall, each
// event arrives as it's sent, not when a buffer fills.
func TestTheEventStreamIsntBufferedByTheEdge(t *testing.T) {
	w, src, _ := watcher(t)
	backend := eventsServer(t, w)
	u, _ := url.Parse(backend.URL)
	proxy := httptest.NewServer(httputil.NewSingleHostReverseProxy(u))
	t.Cleanup(proxy.Close)
	s := openStream(t, proxy.URL+edgefall.EventsPath)
	s.next()
	src.err, src.p = nil, edgefall.Phase{State: "updating", Kind: "update"}
	w.Poll(context.Background())
	if e := s.next(); e.State != "updating" {
		t.Fatalf("%+v", e)
	}
}

// The edge's gate lets the stream through in every state, like the other
// /_box/ paths.
func TestTheGateLetsTheEventStreamThrough(t *testing.T) {
	if rec := gate(t, boxstate.Updating, edgefall.EventsPath, "192.0.2.10"); rec.Code != http.StatusNoContent {
		t.Fatalf("%d", rec.Code)
	}
}

func pushServer(t *testing.T, w *edgefall.Watcher) *http.Client {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "push.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: edgefall.PushHandler(w, nil), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
}

func push(t *testing.T, c *http.Client, p edgefall.Phase) {
	t.Helper()
	b, _ := json.Marshal(p)
	res, err := c.Post("http://edgefall"+edgefall.PushPath, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("push: %d", res.StatusCode)
	}
}

// accessd's push takes effect at once, and its answer comes only once an
// open stream has been sent the event: what accessd does next (stopping a
// service, rebooting) happens after every tab was told.
func TestAPushIsSentBeforeItIsAnswered(t *testing.T) {
	w, src, _ := watcher(t)
	src.err, src.p = nil, edgefall.Phase{ProductInstalled: true, ProductRunning: true, State: "running"}
	w.Poll(context.Background())
	s := openStream(t, eventsServer(t, w).URL+edgefall.EventsPath)
	s.next()
	push(t, pushServer(t, w), edgefall.Phase{ProductInstalled: true, ProductRunning: true, State: "updating", Kind: "product-apply", Step: "switch", Detail: "Switching slots"})
	// The event was flushed before the push was answered; the stream's
	// reader may still be handing it over, so wait a moment for it.
	select {
	case e := <-s.events:
		if e.State != "updating" || kind(e) != "product-apply" || e.Step != "switch" {
			t.Fatalf("%+v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("the push was answered before the stream had the event")
	}
	if w.State() != boxstate.Updating {
		t.Fatalf("state %q", w.State())
	}
}

// A pushed reboot holds like an announced one; a push that resets it (the
// reboot was refused) lets the box's own state through again.
func TestAPushedRebootHoldsUntilReset(t *testing.T) {
	w, src, _ := watcher(t)
	src.err, src.p = nil, edgefall.Phase{ProductInstalled: true, ProductRunning: true, State: "running"}
	w.Poll(context.Background())
	c := pushServer(t, w)
	push(t, c, edgefall.Phase{ProductInstalled: true, ProductRunning: true, State: "rebooting"})
	w.Poll(context.Background())
	if w.State() != boxstate.Rebooting {
		t.Fatalf("after a poll: %q", w.State())
	}
	push(t, c, edgefall.Phase{ProductInstalled: true, ProductRunning: true, State: "running", Reset: true})
	w.Poll(context.Background())
	if w.State() != boxstate.Running {
		t.Fatalf("after the reset: %q", w.State())
	}
}

// Only a POST of a valid state is taken.
func TestAPushIsChecked(t *testing.T) {
	w, _, _ := watcher(t)
	h := edgefall.PushHandler(w, nil)
	for _, c := range []struct {
		method, body string
		want         int
	}{
		{http.MethodGet, "", http.StatusMethodNotAllowed},
		{http.MethodPost, `{"state":"exploded"}`, http.StatusBadRequest},
		{http.MethodPost, `not json`, http.StatusBadRequest},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(c.method, edgefall.PushPath, strings.NewReader(c.body)))
		if rec.Code != c.want {
			t.Fatalf("%s %q: %d, want %d", c.method, c.body, rec.Code, c.want)
		}
	}
	if w.State() != boxstate.Starting {
		t.Fatalf("state %q", w.State())
	}
}
