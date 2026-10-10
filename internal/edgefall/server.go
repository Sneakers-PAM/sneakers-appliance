// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package edgefall is sneakers-edgefall, the product edge's fallback
// (platform design, Section 3.2; docs/edge-fallback.md). It serves three
// things and nothing else: the box state at /_box/state, the poller
// product pages load from /_box/poll.js, the installed product's logo at
// /_box/logo when its bundle carries one, and the branded box-state page,
// with 503, for every other request. It never serves product content and
// never proxies. Traefik reaches it on loopback for /_box/ and for its
// error pages; while k0s doesn't run, edgefall answers 80 and 443 itself.
package edgefall

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxstate"
)

// The paths edgefall answers with something other than the page.
const (
	StatePath  = "/_box/state"
	PollerPath = "/_box/poll.js"
	LogoPath   = "/_box/logo"
)

// StateHeader carries the state on the page, so the poller tells the page
// from the product once the box is back.
const StateHeader = "Sneakers-Box-State"

// retryAfter is the page's Retry-After, in seconds.
const retryAfter = "10"

//go:embed assets/poll.js
var poller []byte

//go:embed assets/page.html
var pageSource string

//go:embed assets/page.css
var pageStyle string

// Words is what the page and the poller say for one state.
type Words struct {
	Title, Note string
}

// words are the page's words, the same as the poller's (a test holds them
// together) and the console's state page.
var words = map[boxstate.State]Words{
	boxstate.Starting:     {"Sneakers-PAM is starting", "This page reloads by itself when it's ready."},
	boxstate.Rebooting:    {"Sneakers-PAM is rebooting", "It comes back by itself. This page reloads when it's ready."},
	boxstate.ShuttingDown: {"Sneakers-PAM is shutting down", "It powers off by itself. Power it on again to use it."},
	boxstate.Updating:     {"Sneakers-PAM is updating", "It comes back by itself when the update is done. This page reloads when it's ready."},
	boxstate.Maintenance:  {"Sneakers-PAM is in maintenance", "It comes back when the maintenance is over. This page reloads when it's ready."},
	boxstate.Failed:       {"Sneakers-PAM failed to start", "The box's administrator can revert or reapply the update on the admin pages. This page reloads when it's back."},
}

// WordsFor is what the page says for s; a running box behind a product
// that doesn't answer yet is starting.
func WordsFor(s boxstate.State) Words {
	if w, ok := words[s]; ok {
		return w
	}
	return words[boxstate.Starting]
}

var page = template.Must(template.New("page").Parse(pageSource))

// Server is edgefall's handler.
type Server struct {
	state  func() boxstate.State
	detail func() string
	look   atomic.Pointer[look]
	key    string
	events *Hub
}

// SetDetail gives the page what accessd says of a failed product: the
// phase and the reason, shown under the words.
func (s *Server) SetDetail(d func() string) { s.detail = d }

// SetEvents serves h's stream at EventsPath, on every listener.
func (s *Server) SetEvents(h *Hub) { s.events = h }

// NewServer serves the state state answers, with the base look until
// LoadBrand finds a brand.
func NewServer(state func() boxstate.State) *Server {
	s := &Server{state: state}
	s.look.Store(newLook(nil))
	return s
}

// pageCSP is the page's policy, its one stylesheet allowed by hash.
func pageCSP(style string) string {
	sum := sha256.Sum256([]byte(style))
	return "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) +
		"'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	st := s.state()
	lk := s.look.Load()
	read := r.Method == http.MethodGet || r.Method == http.MethodHead
	switch {
	case read && r.URL.Path == StatePath && r.URL.RawPath == "":
		h.Set("Content-Type", "application/json")
		b, _ := json.Marshal(struct {
			State string     `json:"state"`
			Brand *stateLook `json:"brand,omitempty"`
		}{string(st), lk.state})
		_, _ = w.Write(b)
	case r.Method == http.MethodGet && r.URL.Path == EventsPath && r.URL.RawPath == "" && s.events != nil:
		s.events.ServeEvents(w, r)
	case read && r.URL.Path == PollerPath && r.URL.RawPath == "":
		h.Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = w.Write(poller)
	case read && r.URL.Path == LogoPath && r.URL.RawPath == "" && lk.logo != nil:
		h.Set("Content-Type", lk.logoType)
		h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		_, _ = w.Write(lk.logo)
	default:
		s.page(w, st, lk)
	}
}

// page is the branded page, with 503: every request but the two above.
func (s *Server) page(w http.ResponseWriter, st boxstate.State, lk *look) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", lk.csp)
	h.Set("Retry-After", retryAfter)
	h.Set(StateHeader, string(st))
	h.Set("Connection", "close")
	var b bytes.Buffer
	wd := WordsFor(st)
	detail := ""
	if st == boxstate.Failed && s.detail != nil {
		detail = s.detail()
	}
	_ = page.Execute(&b, struct {
		State               string
		Title, Note, Detail string
		Style               template.CSS
		LogoURI             template.URL
	}{string(st), wd.Title, wd.Note, detail, template.CSS(lk.style), template.URL(lk.logoURI)}) // #nosec G203 -- the embedded stylesheet and validated #rrggbb colours, pinned by the CSP's hash; the checked logo as a data: URI
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write(b.Bytes())
}

var hostname = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$|^\[[0-9A-Fa-f:.]{2,45}\]$`)

// Redirect is port 80's handler: everything goes to https on the same
// host, as Traefik's 80 does.
func Redirect() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if i := strings.LastIndex(host, ":"); i > 0 && !strings.HasSuffix(host, "]") {
			host = host[:i]
		}
		if !hostname.MatchString(host) {
			http.Error(w, "bad host", http.StatusBadRequest)
			return
		}
		w.Header().Set("Connection", "close")
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently) // #nosec G710 -- the same host, checked above, over https: what Traefik's 80 does
	})
}

// GatePath is the edge's forward check for every request on 443 (a
// Traefik forwardAuth middleware on the websecure entry point), on the
// loopback listener only.
const GatePath = "/_box/gate"

// Gate lets a product request through (204) only while the box is
// running: after k0s starts and during a product apply or revert the box
// says starting or updating until the product is ready
// (docs/edge-fallback.md), and every request gets the branded page with
// 503 instead, so no one signs in to, and no agent writes to, a product
// that isn't ready. The poller's own paths always pass, and so does the
// box itself on loopback, whose readiness check asks the product through
// the edge before the gate opens. The forwarded headers are Traefik's own:
// it drops a client's, so the last X-Forwarded-For entry is the peer.
func (s *Server) Gate(w http.ResponseWriter, r *http.Request) {
	st := s.state()
	if st == boxstate.Running || boxPath(r.Header.Get("X-Forwarded-Uri")) || loopbackPeer(r.Header.Get("X-Forwarded-For")) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	s.page(w, st, s.look.Load())
}

// boxPath is whether a forwarded URI is one of edgefall's own paths, plain:
// no dot segments and no escapes.
func boxPath(uri string) bool {
	return strings.HasPrefix(uri, "/_box/") && !strings.Contains(uri, "..") && !strings.Contains(uri, "%")
}

// loopbackPeer is whether the last X-Forwarded-For entry is a loopback
// address.
func loopbackPeer(xff string) bool {
	parts := strings.Split(xff, ",")
	a, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1]))
	return err == nil && a.IsLoopback()
}

// HandoffPath is where the product's edge asks for 80 and 443 (a POST, on
// the loopback listener only), from an init container that runs just
// before Traefik starts and binds them.
const HandoffPath = "/_box/edge-handoff"

// LocalHandler is the loopback listener's handler: the edge's handoff and
// its gate, then h for everything else.
func LocalHandler(h *Server, handoff func() bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.URL.Path == GatePath && r.URL.RawPath == "" {
			h.Gate(w, r)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == HandoffPath && r.URL.RawPath == "" {
			handoff()
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// LocalAddr is where Traefik reaches edgefall, on loopback only.
const LocalAddr = "127.0.0.1:9180"
