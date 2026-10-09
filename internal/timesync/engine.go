// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package timesync

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Poll and adjustment limits.
const (
	// MaxServers matches the network settings' NTP limit.
	MaxServers = 4
	// MinPoll is the steady-state poll interval (NTP MINPOLL, 2^6 s).
	MinPoll = 64 * time.Second
	// MaxPoll is the back-off ceiling while a server does not answer (NTP's
	// default maximum, 2^10 s).
	MaxPoll = 1024 * time.Second
	// PollFloor is the RFC 4330 section 10 hard floor: a client must never
	// poll one server more often than this.
	PollFloor = 15 * time.Second
	// StepThreshold is RFC 5905 STEPT: offsets above it are stepped, smaller
	// ones slewed.
	StepThreshold = 128 * time.Millisecond
	// MaxSlew is the largest backwards offset a running box slews rather
	// than steps. The kernel absorbs a slew at up to 500 ppm, so a clock
	// that booted a few seconds fast is right again within hours and never
	// runs backwards; a larger error is stepped, and reported (OnStep).
	MaxSlew = 30 * time.Second

	// bootAttempts is one request plus up to three retries per server at
	// boot, the same burst as NTP's iburst. The spacing is a retransmission
	// of an unanswered request, not the poll interval PollFloor governs.
	bootAttempts = 4

	defaultQueryTimeout = time.Second
	defaultRetryGap     = 2 * time.Second
	// defaultBootBudget bounds the boot sync so an unreachable server never
	// holds up a node that must stay manageable.
	defaultBootBudget = 10 * time.Second
)

// LevelTrace is below slog's Debug, for raw header fields.
const LevelTrace = slog.Level(-8)

// Clock is the node's real-time clock. The system implementation steps with
// clock_settime and slews with adjtimex; tests use a fake so they never touch
// the host clock.
type Clock interface {
	// Now reads the clock. Its value must carry a monotonic reading so the
	// round-trip delay survives an adjustment mid-query.
	Now() time.Time
	// Step moves the clock by d at once.
	Step(d time.Duration) error
	// Slew asks the kernel to absorb d gradually.
	Slew(d time.Duration) error
	// MarkSynced tells the kernel the clock is synchronised to within
	// maxErr, which lets it keep the hardware clock close.
	MarkSynced(maxErr time.Duration) error
}

// Config configures an Engine.
type Config struct {
	// Servers are the time servers, at most MaxServers, each an IPv4 or IPv6 literal
	// or a hostname, already validated.
	Servers []string
	// Source is where Servers came from. TIME_SOURCE_NONE (or no servers)
	// makes the engine inert: NOT_CONFIGURED, never gating signing.
	Source Source
	Clock  Clock
	Floor  *Floor
	Logger *slog.Logger

	// Resolve looks up a hostname server's addresses. Nil uses the
	// system resolver, so a DNS change is picked up at the next poll.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// Dial opens a connected UDP socket to a server. Nil dials udp; the
	// connected socket makes the kernel drop datagrams from any other peer.
	Dial func(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
	// Rand supplies the request nonce. Nil uses crypto/rand.
	Rand io.Reader
	// OnStep, when set, is told about every step after it's made: the
	// offset, the server and whether it was the boot sync's. netd audits
	// it.
	OnStep func(offset time.Duration, server string, boot bool)

	QueryTimeout time.Duration
	RetryGap     time.Duration
	BootBudget   time.Duration
}

type server struct {
	name     string
	interval time.Duration
	nextDue  time.Time
	// disabled is the kiss code that stopped this server until reboot.
	disabled string
}

// Engine is the client-only SNTP synchroniser: one bounded sync at boot, then
// periodic polls. It never serves time.
type Engine struct {
	cfg     Config
	log     *slog.Logger
	servers []*server

	// round serialises sync rounds.
	round sync.Mutex

	mu         sync.Mutex
	state      State
	syncedOnce bool
	lastServer string
	lastOffset time.Duration
	hasOffset  bool
	stratum    uint32
	lastSync   time.Time
	stepped    bool
	lastErr    string
}

// New builds an Engine. It does no I/O.
func New(cfg Config) (*Engine, error) {
	if len(cfg.Servers) > MaxServers {
		return nil, fmt.Errorf("timesync: at most %d servers, got %d", MaxServers, len(cfg.Servers))
	}
	if cfg.Clock == nil {
		return nil, errors.New("timesync: a clock is required")
	}
	if cfg.Floor == nil {
		return nil, errors.New("timesync: a clock floor is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Resolve == nil {
		cfg.Resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	if cfg.Dial == nil {
		cfg.Dial = func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", addr.String())
		}
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.QueryTimeout <= 0 {
		cfg.QueryTimeout = defaultQueryTimeout
	}
	if cfg.RetryGap <= 0 {
		cfg.RetryGap = defaultRetryGap
	}
	if cfg.BootBudget <= 0 {
		cfg.BootBudget = defaultBootBudget
	}
	if len(cfg.Servers) == 0 {
		cfg.Source = SourceNone
	}
	e := &Engine{cfg: cfg, log: cfg.Logger.With("component", "timesync")}
	for _, s := range cfg.Servers {
		e.servers = append(e.servers, &server{name: s, interval: MinPoll})
	}
	if e.configured() {
		e.state = StatePending
	} else {
		e.state = StateNotConfigured
	}
	return e, nil
}

func (e *Engine) configured() bool {
	return e.cfg.Source != SourceNone && len(e.servers) > 0
}

// SignAllowed reports whether the signing gate is open: always with no time
// source, otherwise once the clock has synced at least once this boot. A later
// failed poll does not close it again: the clock was corrected and now drifts
// only at the hardware rate, and the status line still reports the failure.
func (e *Engine) SignAllowed() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.state == StateNotConfigured || e.syncedOnce
}

// Status returns the current state for GetStatus.
func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := Status{
		State:         e.state,
		Source:        e.cfg.Source,
		Servers:       append([]string(nil), e.cfg.Servers...),
		LastServer:    e.lastServer,
		Stratum:       e.stratum,
		SteppedAtBoot: e.stepped,
		LastError:     e.lastErr,
	}
	if e.hasOffset {
		st.LastOffset = e.lastOffset
		st.HasOffset = true
	}
	if !e.lastSync.IsZero() {
		st.LastSync = e.lastSync
	}
	return st
}

// NoteIssued raises the clock floor to an issued certificate's notBefore, so
// no later sync can step the clock behind a certificate already handed out.
func (e *Engine) NoteIssued(notBefore time.Time) {
	if err := e.cfg.Floor.Advance(notBefore); err != nil {
		e.log.Error("clock floor: could not record an issued notBefore", "not_before", notBefore, "err", err)
		return
	}
	e.log.Log(context.Background(), LevelTrace, "clock floor raised to an issued notBefore", "not_before", notBefore)
}

// Shutdown records the clock in the floor at a clean shutdown, but only if it
// synced this boot: an unsynced clock may be fast, and baking a fast time into
// the floor would block the correction on the next boot.
func (e *Engine) Shutdown() {
	e.mu.Lock()
	synced := e.syncedOnce
	e.mu.Unlock()
	if !synced {
		e.log.Debug("clock floor: not recorded at shutdown, the clock never synced this boot")
		return
	}
	now := e.cfg.Clock.Now()
	if err := e.cfg.Floor.Advance(now); err != nil {
		e.log.Error("clock floor: could not record the clock at shutdown", "err", err)
		return
	}
	e.log.Info("clock floor recorded at shutdown", "floor", now.UTC())
}

// BootSync runs the bounded boot sync: one request per server, retried up to
// three times while unanswered, within the boot budget. It steps the clock
// when the offset exceeds StepThreshold and slews otherwise. It never fails:
// a node that cannot reach its servers boots on its hardware clock, with
// signing gated until a later poll succeeds.
func (e *Engine) BootSync(ctx context.Context) {
	if !e.configured() {
		e.log.Info("no time source configured; running on the hardware clock, signing is not gated")
		return
	}
	e.round.Lock()
	defer e.round.Unlock()
	start := time.Now()
	e.log.Info("boot time sync starting", "source", e.cfg.Source.String(), "servers", strings.Join(e.cfg.Servers, ","), "floor", e.cfg.Floor.Get())
	ctx, cancel := context.WithTimeout(ctx, e.cfg.BootBudget)
	defer cancel()

	pending := e.enabled()
	var samples []Sample
	errs := map[string]error{}
	for attempt := 0; attempt < bootAttempts && len(pending) > 0; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(e.cfg.RetryGap):
			}
			if ctx.Err() != nil {
				break
			}
			e.log.Debug("boot time sync retrying unanswered servers", "attempt", attempt+1, "servers", names(pending))
		}
		var retry []*server
		for i, r := range e.queryAll(ctx, pending) {
			srv := pending[i]
			if r.err == nil {
				samples = append(samples, r.sample)
				delete(errs, srv.name)
				continue
			}
			errs[srv.name] = r.err
			if e.handleKiss(srv, r.err) {
				continue
			}
			retry = append(retry, srv)
		}
		pending = retry
	}
	now := time.Now()
	for _, s := range e.servers {
		s.nextDue = now.Add(s.interval)
	}
	e.apply(samples, errs, true)
	e.log.Debug("boot time sync finished", "duration", time.Since(start), "replies", len(samples))
}

// Run polls until ctx is done, waking when the next server is due.
func (e *Engine) Run(ctx context.Context) {
	if !e.configured() {
		return
	}
	e.log.Debug("periodic time sync started")
	for {
		wait := e.untilNextDue()
		if wait < 0 {
			e.log.Warn("periodic time sync stopped: every server refused service")
			return
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			e.log.Debug("periodic time sync stopped")
			return
		case <-t.C:
		}
		e.sync(ctx, false)
	}
}

// SyncNow runs one round over every enabled server now, for the network
// checks. It honours no poll interval, so it's for a person's request only.
func (e *Engine) SyncNow(ctx context.Context) {
	if !e.configured() {
		return
	}
	e.sync(ctx, true)
}

// untilNextDue is how long until the earliest enabled server is due, never
// less than PollFloor, or -1 when no server is enabled.
func (e *Engine) untilNextDue() time.Duration {
	e.round.Lock()
	defer e.round.Unlock()
	var next time.Time
	for _, s := range e.servers {
		if s.disabled != "" {
			continue
		}
		if next.IsZero() || s.nextDue.Before(next) {
			next = s.nextDue
		}
	}
	if next.IsZero() {
		return -1
	}
	return max(time.Until(next), PollFloor)
}

// sync runs one periodic round over the servers that are due (all enabled
// ones when force is set).
func (e *Engine) sync(ctx context.Context, force bool) {
	e.round.Lock()
	defer e.round.Unlock()
	now := time.Now()
	var due []*server
	for _, s := range e.enabled() {
		if force || !now.Before(s.nextDue) {
			due = append(due, s)
		}
	}
	if len(due) == 0 {
		e.log.Log(ctx, LevelTrace, "time sync round skipped: no server is due")
		return
	}
	var samples []Sample
	errs := map[string]error{}
	for i, r := range e.queryAll(ctx, due) {
		srv := due[i]
		if r.err == nil {
			samples = append(samples, r.sample)
			srv.interval = MinPoll
		} else {
			errs[srv.name] = r.err
			if !e.handleKiss(srv, r.err) {
				srv.interval = backoff(srv.interval)
				e.log.Debug("time server did not answer; backing off", "server", srv.name, "interval", srv.interval)
			}
		}
		srv.nextDue = time.Now().Add(srv.interval)
	}
	e.apply(samples, errs, false)
}

// handleKiss acts on a Kiss-o'-Death and reports whether err was one the
// client must not retry (RFC 5905 section 7.4). DENY and RSTR stop queries to
// that server until reboot; RATE doubles its poll interval. Other codes are
// treated as no reply.
func (e *Engine) handleKiss(srv *server, err error) bool {
	var kiss *KissError
	if !errors.As(err, &kiss) {
		return false
	}
	switch kiss.Code {
	case KissDeny, KissRstr:
		srv.disabled = kiss.Code
		e.log.Warn("time server sent kiss-o'-death; not querying it again until reboot", "server", srv.name, "code", kiss.Code)
		return true
	case KissRate:
		srv.interval = backoff(srv.interval)
		e.log.Warn("time server sent kiss-o'-death RATE; reducing the poll rate", "server", srv.name, "interval", srv.interval)
		return true
	}
	e.log.Warn("time server sent a kiss-o'-death; treating it as no reply", "server", srv.name, "code", kiss.Code)
	return false
}

func backoff(d time.Duration) time.Duration {
	return min(max(2*d, PollFloor), MaxPoll)
}

func (e *Engine) enabled() []*server {
	var out []*server
	for _, s := range e.servers {
		if s.disabled == "" {
			out = append(out, s)
		}
	}
	return out
}

type result struct {
	sample Sample
	err    error
}

// queryAll queries servers concurrently so one slow server cannot use up the
// others' share of the boot budget.
func (e *Engine) queryAll(ctx context.Context, servers []*server) []result {
	out := make([]result, len(servers))
	var wg sync.WaitGroup
	for i, s := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sample, err := e.query(ctx, s.name)
			if err != nil {
				e.log.Warn("time server reply rejected or missing", "server", s.name, "err", err)
			}
			out[i] = result{sample: sample, err: err}
		}()
	}
	wg.Wait()
	return out
}

// query performs one client/server exchange with name.
func (e *Engine) query(ctx context.Context, name string) (Sample, error) {
	start := time.Now()
	addr, err := e.resolve(ctx, name)
	if err != nil {
		return Sample{}, err
	}
	ap := netip.AddrPortFrom(addr, Port)
	conn, err := e.cfg.Dial(ctx, ap)
	if err != nil {
		return Sample{}, fmt.Errorf("timesync: %s: dial %s: %w", name, ap, err)
	}
	defer func() { _ = conn.Close() }()

	var nb [8]byte
	if _, err := io.ReadFull(e.cfg.Rand, nb[:]); err != nil {
		return Sample{}, fmt.Errorf("timesync: request nonce: %w", err)
	}
	nonce := Timestamp(binary.BigEndian.Uint64(nb[:]))
	if nonce == 0 {
		nonce = 1
	}
	deadline := time.Now().Add(e.cfg.QueryTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return Sample{}, fmt.Errorf("timesync: %s: %w", name, err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	pivot := e.pivot()
	t1 := e.cfg.Clock.Now()
	if _, err := conn.Write(NewRequest(nonce).Marshal()); err != nil {
		return Sample{}, fmt.Errorf("timesync: %s: send: %w", name, err)
	}
	e.log.Log(ctx, LevelTrace, "time request sent", "server", name, "addr", ap.String())
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		t4 := e.cfg.Clock.Now()
		if err != nil {
			return Sample{}, fmt.Errorf("timesync: %s: no reply: %w", name, err)
		}
		h, err := ParseHeader(buf[:n])
		if err != nil {
			e.log.Warn("time reply discarded", "server", name, "err", err)
			continue
		}
		e.log.Log(ctx, LevelTrace, "time reply header", "server", name,
			"li", h.Leap, "vn", h.Version, "mode", h.Mode, "stratum", h.Stratum, "poll", h.Poll,
			"precision", h.Precision, "root_delay", h.RootDelay.Duration(), "root_dispersion", h.RootDispersion.Duration(),
			"ref_id", fmt.Sprintf("%x", h.ReferenceID), "origin_matches", h.Origin == nonce)
		// A reply that does not echo this request's nonce may be a late
		// answer to an earlier one; keep waiting for ours.
		if h.Mode == ModeServer && h.Origin != nonce {
			e.log.Warn("time reply discarded: origin does not match this request", "server", name)
			continue
		}
		if err := ValidateReply(h, nonce); err != nil {
			return Sample{}, fmt.Errorf("%w (server %s)", err, name)
		}
		offset, delay, err := Compute(t1, t4, h, pivot)
		if err != nil {
			return Sample{}, fmt.Errorf("%w (server %s)", err, name)
		}
		s := Sample{Server: name, Addr: ap.String(), Offset: offset, Delay: delay, Stratum: h.Stratum, RootDistance: RootDistance(h)}
		e.log.Debug("time poll", "server", name, "addr", ap.String(), "offset", offset, "delay", delay,
			"stratum", h.Stratum, "duration", time.Since(start))
		return s, nil
	}
}

func (e *Engine) resolve(ctx context.Context, name string) (netip.Addr, error) {
	if a, err := netip.ParseAddr(name); err == nil {
		return a, nil
	}
	addrs, err := e.cfg.Resolve(ctx, name)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("timesync: resolve %s: %w", name, err)
	}
	// The resolver sorts by RFC 6724, which puts first the family the box
	// can reach.
	for _, a := range addrs {
		if a.IsValid() {
			a = a.Unmap()
			e.log.Log(ctx, LevelTrace, "time server resolved", "server", name, "addr", a.String())
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("timesync: resolve %s: no address", name)
}

// pivot is the time the era of a reply is decoded around: the clock, or the
// floor when the clock is behind it (a hardware clock reset to its epoch).
func (e *Engine) pivot() time.Time {
	now := e.cfg.Clock.Now()
	if f := e.cfg.Floor.Get(); now.Before(f) {
		return f
	}
	return now
}

// apply combines one round and adjusts the clock.
func (e *Engine) apply(samples []Sample, errs map[string]error, boot bool) {
	if len(samples) == 0 {
		e.fail(joinErrs(errs), slog.LevelWarn)
		return
	}
	s, err := Combine(samples)
	if err != nil {
		e.fail(err.Error(), slog.LevelWarn)
		return
	}
	abs := absDuration(s.Offset)
	var step bool
	switch {
	case abs <= StepThreshold:
	case boot || s.Offset > 0:
		step = true
	case abs <= MaxSlew:
		// A running box slews a small error back, so its clock never runs
		// backwards for it.
		e.log.Info("clock ahead of the servers; slewing it back", "server", s.Server, "offset", s.Offset)
	default:
		e.log.Warn("clock far ahead of the servers; stepping it back", "server", s.Server, "offset", s.Offset)
		step = true
	}
	now := e.cfg.Clock.Now()
	if step {
		// Only a step can move the clock backwards; a slew only slows it,
		// so the floor is checked for steps.
		target := now.Add(s.Offset)
		if floor := e.cfg.Floor.Get(); target.Before(floor) {
			msg := fmtFloorError(target, floor)
			e.log.Error("clock step refused: "+msg, "server", s.Server, "offset", s.Offset, "delta", floor.Sub(target))
			e.fail(msg+" (server "+s.Server+")", slog.LevelError)
			return
		}
		if err := e.cfg.Clock.Step(s.Offset); err != nil {
			e.log.Error("clock step failed", "offset", s.Offset, "err", err)
			e.fail(fmt.Sprintf("set clock: %v", err), slog.LevelError)
			return
		}
		e.log.Info("clock stepped", "server", s.Server, "offset", s.Offset, "boot", boot)
		if e.cfg.OnStep != nil {
			e.cfg.OnStep(s.Offset, s.Server, boot)
		}
	} else {
		if err := e.cfg.Clock.Slew(s.Offset); err != nil {
			e.log.Error("clock slew failed", "offset", s.Offset, "err", err)
			e.fail(fmt.Sprintf("slew clock: %v", err), slog.LevelError)
			return
		}
		e.log.Debug("clock slewing", "server", s.Server, "offset", s.Offset)
	}
	if err := e.cfg.Clock.MarkSynced(s.RootDistance + s.Delay/2); err != nil {
		e.log.Warn("could not mark the kernel clock synchronised", "err", err)
	}
	synced := e.cfg.Clock.Now()
	if err := e.cfg.Floor.Advance(synced); err != nil {
		e.log.Error("clock floor: could not record the synced time", "err", err)
	}
	e.succeed(s, synced, boot && step)
}

func (e *Engine) fail(msg string, level slog.Level) {
	e.mu.Lock()
	prev := e.state
	e.state = StateUnsynced
	e.lastErr = msg
	e.mu.Unlock()
	if prev != StateUnsynced {
		e.log.Info("time sync state changed", "from", prev.String(), "to", "UNSYNCED")
	}
	e.log.Log(context.Background(), level, "time sync round did not adjust the clock", "reason", msg)
}

func (e *Engine) succeed(s Sample, at time.Time, stepped bool) {
	e.mu.Lock()
	prev := e.state
	first := !e.syncedOnce
	e.state = StateSynced
	e.syncedOnce = true
	e.lastServer = s.Server
	e.lastOffset = s.Offset
	e.hasOffset = true
	e.stratum = uint32(s.Stratum)
	e.lastSync = at
	e.lastErr = ""
	if stepped {
		e.stepped = true
	}
	e.mu.Unlock()
	if prev != StateSynced {
		e.log.Info("time sync state changed", "from", prev.String(), "to", "SYNCED", "server", s.Server, "offset", s.Offset)
	}
	if first {
		e.log.Info("clock synced for the first time this boot; the signing gate is open", "server", s.Server)
	}
}

// fmtFloorError is the reason a step below the floor was refused.
func fmtFloorError(target, floor time.Time) string {
	return fmt.Sprintf("server time %s is behind already-issued certificates or the last good sync (floor %s)",
		target.UTC().Format(time.RFC3339Nano), floor.UTC().Format(time.RFC3339Nano))
}

func joinErrs(errs map[string]error) string {
	if len(errs) == 0 {
		return "no server answered"
	}
	keys := make([]string, 0, len(errs))
	for k := range errs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, errs[k].Error())
	}
	return strings.Join(parts, "; ")
}

func names(servers []*server) string {
	n := make([]string, 0, len(servers))
	for _, s := range servers {
		n = append(n, s.name)
	}
	return strings.Join(n, ",")
}

// interval reports a server's poll interval, for tests.
func (e *Engine) interval(name string) time.Duration {
	e.round.Lock()
	defer e.round.Unlock()
	for _, s := range e.servers {
		if s.name == name {
			return s.interval
		}
	}
	return 0
}
