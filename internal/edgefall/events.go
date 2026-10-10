// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package edgefall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxstate"
)

// EventsPath is the box state as a server-sent-events stream
// (docs/edge-fallback.md#the-event-stream), on 443 and on loopback.
const EventsPath = "/_box/events"

// The stream's kinds: what started the state, null otherwise.
const (
	KindUpdate       = "update"
	KindReboot       = "reboot"
	KindShutdown     = "shutdown"
	KindProductApply = "product-apply"
)

// retryMS is the reconnect delay the stream asks clients for, once.
const retryMS = 2000

// heartbeat is how often an idle stream gets a comment line, so proxies
// keep it open.
var heartbeat atomic.Int64

func init() { heartbeat.Store(int64(15 * time.Second)) }

// SetHeartbeat sets the heartbeat for a test and returns the undo.
func SetHeartbeat(d time.Duration) func() {
	old := heartbeat.Swap(int64(d))
	return func() { heartbeat.Store(old) }
}

// Event is one state event as the stream sends it.
type Event struct {
	State  string  `json:"state"`
	Kind   *string `json:"kind"`
	Step   string  `json:"step"`
	Detail string  `json:"detail"`
	Since  string  `json:"since"`
	Seq    int64   `json:"seq"`
}

// subscriber is one open stream: it holds the latest event it hasn't
// sent yet (a slow client skips to the newest, it never falls behind)
// and the seq it last wrote out.
type subscriber struct {
	wake chan struct{}
	mu   sync.Mutex
	next *Event
	sent int64
}

// Hub holds the current event and every open stream.
type Hub struct {
	mu   sync.Mutex
	cur  Event
	subs map[*subscriber]struct{}
	now  func() time.Time
	// flushed is signalled whenever a stream wrote an event out.
	flushed chan struct{}
}

// NewHub starts at starting, before anything is known.
func NewHub() *Hub {
	h := &Hub{subs: map[*subscriber]struct{}{}, now: time.Now, flushed: make(chan struct{}, 1)}
	h.cur = Event{State: string(boxstate.Starting), Seq: 1, Since: h.now().UTC().Format(time.RFC3339)}
	return h
}

// Current is the event a new stream gets first.
func (h *Hub) Current() Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cur
}

// Set makes state, kind, step and detail the current event when any of
// them changed, and hands it to every open stream; it returns the
// current event.
func (h *Hub) Set(state boxstate.State, kind, step, detail string) Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	var k *string
	if kind != "" {
		k = &kind
	}
	same := h.cur.State == string(state) && h.cur.Step == step && h.cur.Detail == detail &&
		((h.cur.Kind == nil && k == nil) || (h.cur.Kind != nil && k != nil && *h.cur.Kind == *k))
	if same {
		return h.cur
	}
	h.cur = Event{State: string(state), Kind: k, Step: step, Detail: detail, Since: h.now().UTC().Format(time.RFC3339), Seq: h.cur.Seq + 1}
	for s := range h.subs {
		e := h.cur
		s.mu.Lock()
		s.next = &e
		s.mu.Unlock()
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
	return h.cur
}

// Sent waits up to max until every open stream has written seq out; false
// when one hasn't by then.
func (h *Hub) Sent(seq int64, max time.Duration) bool {
	deadline := time.After(max)
	for {
		h.mu.Lock()
		behind := false
		for s := range h.subs {
			s.mu.Lock()
			if s.sent < seq {
				behind = true
			}
			s.mu.Unlock()
		}
		h.mu.Unlock()
		if !behind {
			return true
		}
		select {
		case <-h.flushed:
		case <-time.After(10 * time.Millisecond):
		case <-deadline:
			return false
		}
	}
}

func (h *Hub) subscribe() (*subscriber, Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := &subscriber{wake: make(chan struct{}, 1)}
	h.subs[s] = struct{}{}
	return s, h.cur
}

func (h *Hub) unsubscribe(s *subscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.subs, s)
}

func writeEvent(w io.Writer, e Event) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: state\ndata: %s\n\n", b)
	return err
}

// ServeEvents is the stream: retry once, the current state at once, then
// every change and a heartbeat comment, each flushed as it's written. It
// lifts the listener's write deadline for itself: a stream stays open.
func (h *Hub) ServeEvents(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	hd := w.Header()
	hd.Set("Content-Type", "text/event-stream")
	hd.Set("Cache-Control", "no-cache")
	hd.Set("X-Accel-Buffering", "no")
	hd.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	s, cur := h.subscribe()
	defer h.unsubscribe(s)
	if _, err := fmt.Fprintf(w, "retry: %d\n\n", retryMS); err != nil {
		return
	}
	if err := writeEvent(w, cur); err != nil || rc.Flush() != nil {
		return
	}
	h.wrote(s, cur.Seq)
	beat := time.NewTicker(time.Duration(heartbeat.Load()))
	defer beat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-beat.C:
			if _, err := io.WriteString(w, ": hb\n\n"); err != nil || rc.Flush() != nil {
				return
			}
		case <-s.wake:
			s.mu.Lock()
			e := s.next
			s.next = nil
			s.mu.Unlock()
			if e == nil {
				continue
			}
			if err := writeEvent(w, *e); err != nil || rc.Flush() != nil {
				return
			}
			h.wrote(s, e.Seq)
		}
	}
}

func (h *Hub) wrote(s *subscriber, seq int64) {
	s.mu.Lock()
	if seq > s.sent {
		s.sent = seq
	}
	s.mu.Unlock()
	select {
	case h.flushed <- struct{}{}:
	default:
	}
}

// PushSocket is the push socket, in edgefall's own 0700 directory.
const PushSocket = "/run/sneakers/edgefall/push.sock"

// PushPath is where accessd hands edgefall a state on its push socket.
const PushPath = "/push"

// pushWait bounds how long a push waits for the open streams to have the
// event before it answers anyway.
const pushWait = 500 * time.Millisecond

// PushHandler is the push socket's handler: accessd POSTs the box's phase
// the moment it changes (an update, a product apply, a reboot or a
// shutdown starting, before anything stops; each step), and the answer
// comes once every open stream was sent it, so what accessd does next
// happens after the tabs were told. after runs once the state is taken
// (the claim follows it).
func PushHandler(w *Watcher, after func()) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != PushPath {
			http.Error(rw, "POST "+PushPath+" only", http.StatusMethodNotAllowed)
			return
		}
		var p Phase
		if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&p); err != nil || !boxstate.Valid(p.State) {
			http.Error(rw, "a phase with a known state", http.StatusBadRequest)
			return
		}
		e := w.Push(p)
		if after != nil {
			after()
		}
		if !w.Events().Sent(e.Seq, pushWait) {
			w.lg.Warn("edgefall: a stream didn't take the pushed state in time; answering anyway", log.F("seq", e.Seq))
		}
		rw.WriteHeader(http.StatusNoContent)
	})
}

// PushClient pushes the box's phase to edgefall's push socket; accessd
// (root) is the one caller.
type PushClient struct {
	Socket string
	once   sync.Once
	hc     *http.Client
}

// Notify posts p and returns once edgefall answered: by then every open
// stream was sent it (or pushWait passed).
func (c *PushClient) Notify(ctx context.Context, p Phase) error {
	c.once.Do(func() {
		c.hc = &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", c.Socket)
			},
			MaxIdleConns: 1,
		}}
	})
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://edgefall"+PushPath, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		return fmt.Errorf("edgefall answered the push with %s", res.Status)
	}
	return nil
}
