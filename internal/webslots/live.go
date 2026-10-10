// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package webslots

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// The sources the served pages come from.
const (
	SourceSlot    = "slot"
	SourceBuiltIn = "built-in"
)

// Served is which pages :8443 serves, as the status file records it.
type Served struct {
	// Version is the served pages' version; the built-in pages carry the
	// running Base OS's.
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	// Source is slot or built-in, and Slot the slot, a or b.
	Source string `json:"source"`
	Slot   string `json:"slot,omitempty"`
	// Reason says why the built-in pages serve, or why the last switch
	// didn't take: a slot that failed its checks, or doesn't fit the
	// running Base OS.
	Reason string `json:"reason,omitempty"`
	// Wanted is the slot and version the current link named at the last
	// load, served or not, so the API can tell a switch that took from
	// one that didn't.
	WantedSlot    string    `json:"wantedSlot,omitempty"`
	WantedVersion string    `json:"wantedVersion,omitempty"`
	At            time.Time `json:"at"`
}

// ReadServed reads the status file the watcher writes.
func ReadServed(p string) (Served, error) {
	b, err := os.ReadFile(p) // #nosec G304 -- the watcher's status file
	if err != nil {
		return Served{}, err
	}
	var s Served
	if err := json.Unmarshal(b, &s); err != nil {
		return Served{}, err
	}
	return s, nil
}

// ServedVersion is the Base Web version the status file at p records: the
// served slot's, or builtin (the running Base OS's own pages) when the
// built-in pages serve or nothing is recorded.
func ServedVersion(p, builtin string) string {
	if s, err := ReadServed(p); err == nil && s.Source == SourceSlot && s.Version != "" {
		return s.Version
	}
	return builtin
}

// Live is the page set :8443 serves, swapped in one step. The set it
// replaced stays answerable for files the new one lacks (an open page's
// hashed assets) until the next swap.
type Live struct {
	mu        sync.RWMutex
	cur, prev fs.FS
	served    Served
}

// NewLive serves builtin, the root's pages, as version.
func NewLive(builtin fs.FS, version string) *Live {
	return &Live{cur: builtin, served: Served{Version: version, Source: SourceBuiltIn}}
}

// Open opens name in the served set, or in the one before it.
func (l *Live) Open(name string) (fs.File, error) {
	l.mu.RLock()
	cur, prev := l.cur, l.prev
	l.mu.RUnlock()
	if cur != nil {
		f, err := cur.Open(name)
		if err == nil || prev == nil {
			return f, err
		}
	}
	if prev != nil {
		return prev.Open(name)
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

// Served is what's served now.
func (l *Live) Served() Served {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.served
}

// Version is the served pages' version, which every API answer carries.
func (l *Live) Version() string { return l.Served().Version }

func (l *Live) swap(f fs.FS, s Served) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cur != nil {
		l.prev = l.cur
	}
	l.cur, l.served = f, s
}

func (l *Live) note(reason, wantSlot, wantVersion string, at time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.served.Reason, l.served.WantedSlot, l.served.WantedVersion, l.served.At = reason, wantSlot, wantVersion, at
}

// Watcher keeps Live on the current slot. At start, and whenever the
// current link or its header changes, it loads the slot (Load, with the
// release key in the running root) and serves it when it passes, fits the
// running Base OS and isn't older than the built-in pages; otherwise it
// keeps what it serves (at start, the built-in pages) and says why. A Base
// OS always ships with its Base Web, and its built-in pages are that Base
// Web, so after a Base OS update the box serves its own newer pages, and
// after a Base OS revert the installed Base Web again. It writes what it serves to StatusFile.
type Watcher struct {
	Slots   Slots
	Key     *ecdsa.PublicKey
	Channel string
	// BaseOS is the running Base OS version; Builtin and BuiltinVersion
	// are its own pages.
	BaseOS         string
	Builtin        fs.FS
	BuiltinVersion string
	Live           *Live
	StatusFile     string
	Logger         log.Logger
	Now            func() time.Time

	seen   string
	synced bool
}

func (w *Watcher) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

func (w *Watcher) logger() log.Logger {
	if w.Logger == nil {
		return log.Nop()
	}
	return w.Logger
}

// state is what the current link names, by slot and header bytes: a
// change means a new load.
func (w *Watcher) state() string {
	dir := w.Slots.CurrentDir()
	if dir == "" {
		return ""
	}
	b, _ := os.ReadFile(filepath.Join(dir, HeaderFile)) // #nosec G304 -- a slot of ours
	return filepath.Base(dir) + "\x00" + string(b)
}

// Sync loads the current slot when it changed since the last Sync.
func (w *Watcher) Sync() {
	st := w.state()
	if w.synced && st == w.seen {
		return
	}
	w.seen, w.synced = st, true
	lg := w.logger()
	dir := w.Slots.CurrentDir()
	if dir == "" {
		if w.Live.Served().Source != SourceBuiltIn {
			w.Live.swap(w.Builtin, Served{Version: w.BuiltinVersion, Source: SourceBuiltIn})
			lg.Info("osadmin: serving the built-in pages", log.F("version", w.BuiltinVersion))
		}
		w.Live.note("no Base Web is installed", "", "", w.now())
		w.write()
		return
	}
	slot := filepath.Base(dir)
	h, _ := w.Slots.Header(linkCurrent)
	p, err := Load(dir, w.Key)
	if err == nil {
		if need := p.Manifest.NeedsBaseOS(w.Channel); !need.Contains(w.BaseOS) {
			err = codes.New(codes.UpgradeCompat, "Base Web %s needs Base OS %s; this box runs Base OS %s", p.Manifest.Version, need.Text(), w.BaseOS)
		}
	}
	if err == nil && Newer(w.BuiltinVersion, p.Manifest.Version) {
		why := "the Base OS's own pages, Base Web " + w.BuiltinVersion + ", are newer than Base Web " + p.Manifest.Version + " in slot " + slot
		if w.Live.Served().Source != SourceBuiltIn {
			w.Live.swap(w.Builtin, Served{Version: w.BuiltinVersion, Source: SourceBuiltIn})
		}
		lg.Info("osadmin: serving the built-in pages, newer than the installed Base Web", log.F("builtin", w.BuiltinVersion), log.F("slot", slot), log.F("version", p.Manifest.Version))
		w.Live.note(why, slot, h.Version, w.now())
		w.write()
		return
	}
	if err != nil {
		why := codes.Describe(err)
		lg.Warn("osadmin: the current Base Web isn't served", log.F("slot", slot), log.F("version", h.Version), log.F("error", why))
		w.Live.note(why, slot, h.Version, w.now())
		w.write()
		return
	}
	w.Live.swap(p.FS, Served{Version: p.Manifest.Version, Commit: p.Manifest.Commit, Source: SourceSlot, Slot: slot, WantedSlot: slot, WantedVersion: h.Version, At: w.now()})
	lg.Info("osadmin: serving the Base Web", log.F("slot", slot), log.F("version", p.Manifest.Version), log.F("files", len(p.Manifest.Files)))
	w.write()
}

func (w *Watcher) write() {
	if w.StatusFile == "" {
		return
	}
	b, err := json.Marshal(w.Live.Served())
	if err != nil {
		return
	}
	tmp := w.StatusFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil { // #nosec G306 -- which pages serve isn't secret
		w.logger().Warn("osadmin: the served pages' status wasn't written", log.F("error", err.Error()))
		return
	}
	if err := os.Rename(tmp, w.StatusFile); err != nil {
		w.logger().Warn("osadmin: the served pages' status wasn't written", log.F("error", err.Error()))
	}
}

// Run syncs at start and every interval until ctx ends.
func (w *Watcher) Run(ctx context.Context, every time.Duration) {
	w.Sync()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.Sync()
		}
	}
}
