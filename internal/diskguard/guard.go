// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package diskguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

// The alert entries.
const (
	ActionAlertStart = "disk.alert.start"
	ActionAlertClear = "disk.alert.clear"
)

// Volume is one filesystem the guard watches.
type Volume struct {
	// Name is a word (state, data, backup); Label the words Status shows.
	Name, Label, Path string
}

// Watch is one product data path the guard samples for growth: Path, and
// optionally the write-ahead log under it (WAL, relative) with the size
// that's too big (WALWarn).
type Watch struct {
	Name, Label, Path, WAL string
	WALWarn                int64
}

// WALPath is the watch's write-ahead log directory.
func (w Watch) WALPath() string { return filepath.Join(w.Path, w.WAL) }

// The kinds of warning.
const (
	WarnSpace        = "space"
	WarnGrowth       = "growth"
	WarnWAL          = "wal"
	WarnAuditArchive = "audit-archive"
)

// Warning is one thing Status warns about.
type Warning struct {
	Kind     string
	Critical bool
	Detail   string
}

// VolumeReport is a volume's use and level.
type VolumeReport struct {
	Volume
	Used, Total, Avail uint64
	Percent            float64
	Level              Level
	Since              time.Time
	// SharedWith names the volume this one is on, when it isn't a
	// filesystem of its own; it has no alert of its own then.
	SharedWith string
	Err        string
}

// WatchReport is a data path's size and growth.
type WatchReport struct {
	Watch
	Size, GrowthPerDay, WALSize int64
}

// Report is what the guard last found.
type Report struct {
	At       time.Time
	Volumes  []VolumeReport
	Watches  []WatchReport
	Warnings []Warning
	Cleanup  *Run
}

// The guard's rhythm.
const (
	DefaultCleanEvery  = time.Hour
	DefaultSampleEvery = time.Hour
	// sampleKeep is how many samples are kept: a day's, hourly, and one.
	sampleKeep = 25
	// fillWarnDays: a volume that would fill within this many days at the
	// last day's rate is growing too fast.
	fillWarnDays = 7
)

// Guard watches the volumes, audits each alert as it starts and clears,
// samples growth and runs the cleanup on its schedule and when a volume
// passes the warning level.
type Guard struct {
	Volumes []Volume
	// Watches are the product's data paths, read again at each sample.
	Watches func() []Watch
	Cleaner *Cleaner
	// Archive reports the OS audit archive's state, for its warning.
	Archive func() *osaudit.ArchiveReport
	Audit   osaudit.Appender
	// StateFile keeps the levels and samples across restarts.
	StateFile   string
	Statfs      func(string) (Usage, error)
	DirSize     func(string) (int64, error)
	Now         func() time.Time
	CleanEvery  time.Duration
	SampleEvery time.Duration
	Logger      log.Logger

	// mu serialises the ticks and the cleanups; rmu guards the report, so
	// Status reads it while a cleanup runs.
	mu     sync.Mutex
	loaded bool
	st     guardState
	rmu    sync.RWMutex
	report Report
}

type levelState struct {
	Level   Level     `json:"level"`
	Since   time.Time `json:"since"`
	Percent float64   `json:"percent"`
}

type sample struct {
	At      time.Time        `json:"at"`
	Volumes map[string]int64 `json:"volumes"`
	Watches map[string]int64 `json:"watches"`
}

type guardState struct {
	Levels    map[string]levelState `json:"levels"`
	Samples   []sample              `json:"samples"`
	LastClean time.Time             `json:"lastClean"`
}

func (g *Guard) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

func (g *Guard) logger() log.Logger {
	if g.Logger == nil {
		return log.Nop()
	}
	return g.Logger
}

func (g *Guard) statfs(p string) (Usage, error) {
	if g.Statfs != nil {
		return g.Statfs(p)
	}
	return Statfs(p)
}

func (g *Guard) dirSize(p string) (int64, error) {
	if g.DirSize != nil {
		return g.DirSize(p)
	}
	return DirSize(p)
}

func (g *Guard) load() {
	if g.loaded {
		return
	}
	g.loaded = true
	g.st = guardState{Levels: map[string]levelState{}}
	if g.StateFile == "" {
		return
	}
	b, err := os.ReadFile(g.StateFile)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			g.logger().Warn("diskguard: the guard's state doesn't read; starting fresh", log.F("error", err.Error()))
		}
		return
	}
	if err := json.Unmarshal(b, &g.st); err != nil {
		g.logger().Warn("diskguard: the guard's state doesn't parse; starting fresh", log.F("error", err.Error()))
		g.st = guardState{}
	}
	if g.st.Levels == nil {
		g.st.Levels = map[string]levelState{}
	}
}

func (g *Guard) save() {
	if g.StateFile == "" {
		return
	}
	b, _ := json.Marshal(g.st)
	tmp := g.StateFile + ".tmp"
	if err := os.MkdirAll(filepath.Dir(g.StateFile), 0o700); err == nil {
		if err = os.WriteFile(tmp, b, 0o600); err == nil {
			err = os.Rename(tmp, g.StateFile)
		}
		if err != nil {
			g.logger().Warn("diskguard: the guard's state wasn't saved", log.F("error", err.Error()))
		}
	}
}

// Tick is the guard's minute: it reads every volume, audits the levels
// that changed, cleans up at once when one went up and on the hour
// otherwise, samples the growth on the hour, and keeps the report.
func (g *Guard) Tick(ctx context.Context) Report {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.load()
	now := g.now()
	vols, rose := g.check(now)
	every := g.CleanEvery
	if every == 0 {
		every = DefaultCleanEvery
	}
	switch {
	case rose && g.Cleaner != nil:
		g.logger().Warn("diskguard: a volume passed its warning level; cleaning up now")
		g.Cleaner.Run(ctx, TriggerAlert, "")
		g.st.LastClean = now
		vols, _ = g.check(g.now())
	case g.Cleaner != nil && now.Sub(g.st.LastClean) >= every:
		g.Cleaner.Run(ctx, TriggerTimer, "")
		g.st.LastClean = now
		vols, _ = g.check(g.now())
	}
	g.sample(now, vols)
	r := g.build(now, vols)
	g.setReport(r)
	g.save()
	return r
}

func (g *Guard) setReport(r Report) {
	g.rmu.Lock()
	defer g.rmu.Unlock()
	g.report = r
}

// CleanUp runs the cleanup now for actor (an admin), then reads the
// volumes again.
func (g *Guard) CleanUp(ctx context.Context, actor string) Run {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.load()
	run := g.Cleaner.Run(ctx, TriggerAdmin, actor)
	now := g.now()
	g.st.LastClean = now
	vols, _ := g.check(now)
	g.setReport(g.build(now, vols))
	g.save()
	return run
}

// Report is the last report.
func (g *Guard) Report() Report {
	g.rmu.RLock()
	defer g.rmu.RUnlock()
	return g.report
}

// check reads every volume and moves each level, auditing the changes;
// rose is set when any level went up.
func (g *Guard) check(now time.Time) ([]VolumeReport, bool) {
	var out []VolumeReport
	devices := map[uint64]string{}
	rose := false
	for _, v := range g.Volumes {
		r := VolumeReport{Volume: v}
		u, err := g.statfs(v.Path)
		if errors.Is(err, fs.ErrNotExist) {
			// Not there yet (product data before a bundle is installed).
			continue
		}
		if err != nil {
			r.Err = err.Error()
			g.logger().Warn("diskguard: a volume doesn't read", log.F("volume", v.Name), log.F("error", r.Err))
			out = append(out, r)
			continue
		}
		r.Used, r.Total, r.Avail, r.Percent = u.Used, u.Total, u.Avail, u.Percent()
		if owner, ok := devices[u.Device]; ok {
			r.SharedWith = owner
			out = append(out, r)
			continue
		}
		devices[u.Device] = v.Name
		cur := g.st.Levels[v.Name]
		next := NextLevel(cur.Level, r.Percent)
		if next != cur.Level {
			g.alert(v, cur.Level, next, r, now)
			if next > cur.Level {
				rose = true
			}
			cur = levelState{Level: next, Since: now}
		}
		cur.Percent = r.Percent
		g.st.Levels[v.Name] = cur
		r.Level, r.Since = cur.Level, cur.Since
		out = append(out, r)
	}
	return out, rose
}

func (g *Guard) alert(v Volume, from, to Level, r VolumeReport, now time.Time) {
	pct := strconv.FormatFloat(math.Round(r.Percent*10)/10, 'f', 1, 64)
	e := osaudit.Entry{Time: now, Actor: guardActor, Target: v.Label + " volume", Outcome: "ok",
		Detail: map[string]string{"volume": v.Name, "percent": pct, "used": strconv.FormatUint(r.Used, 10), "total": strconv.FormatUint(r.Total, 10)}}
	if to > from {
		e.Action = ActionAlertStart
		e.Detail["level"] = to.String()
		g.logger().Warn("diskguard: alert starts", log.F("volume", v.Name), log.F("level", to.String()), log.F("percent", pct))
	} else {
		e.Action = ActionAlertClear
		e.Detail["level"] = from.String()
		e.Detail["now"] = to.String()
		g.logger().Info("diskguard: alert clears", log.F("volume", v.Name), log.F("level", from.String()), log.F("now", to.String()), log.F("percent", pct))
	}
	if g.Audit != nil {
		if err := g.Audit.Append(e); err != nil {
			g.logger().Error(err, "diskguard: the alert's audit entry wasn't written", log.F("volume", v.Name))
		}
	}
}

// sample records the volumes' use and the data paths' sizes once per
// SampleEvery.
func (g *Guard) sample(now time.Time, vols []VolumeReport) {
	every := g.SampleEvery
	if every == 0 {
		every = DefaultSampleEvery
	}
	if n := len(g.st.Samples); n > 0 && now.Sub(g.st.Samples[n-1].At) < every && !now.Before(g.st.Samples[n-1].At) {
		return
	}
	s := sample{At: now, Volumes: map[string]int64{}, Watches: map[string]int64{}}
	for _, v := range vols {
		if v.Err == "" && v.SharedWith == "" {
			s.Volumes[v.Name] = int64(v.Used) // #nosec G115 -- a volume size fits an int64
		}
	}
	for _, w := range g.watches() {
		if n, err := g.dirSize(w.Path); err == nil {
			s.Watches[w.Name] = n
		}
	}
	g.st.Samples = append(g.st.Samples, s)
	if len(g.st.Samples) > sampleKeep {
		g.st.Samples = g.st.Samples[len(g.st.Samples)-sampleKeep:]
	}
	g.logger().Debug("diskguard: sampled", log.F("volumes", len(s.Volumes)), log.F("watches", len(s.Watches)))
}

func (g *Guard) watches() []Watch {
	if g.Watches == nil {
		return nil
	}
	return g.Watches()
}

// rate is how fast name grew per day over the last day's samples: from the
// oldest sample at most a day old (and at least an hour) to the newest.
func (g *Guard) rate(now time.Time, get func(sample) (int64, bool)) (int64, bool) {
	n := len(g.st.Samples)
	if n < 2 {
		return 0, false
	}
	last := g.st.Samples[n-1]
	lv, ok := get(last)
	if !ok {
		return 0, false
	}
	for _, s := range g.st.Samples[:n-1] {
		if now.Sub(s.At) > 25*time.Hour {
			continue
		}
		span := last.At.Sub(s.At)
		if span < time.Hour {
			return 0, false
		}
		fv, ok := get(s)
		if !ok {
			continue
		}
		return int64(float64(lv-fv) * float64(24*time.Hour) / float64(span)), true
	}
	return 0, false
}

func (g *Guard) build(now time.Time, vols []VolumeReport) Report {
	r := Report{At: now, Volumes: vols}
	if g.Cleaner != nil {
		r.Cleanup = g.Cleaner.Last()
	}
	for _, v := range vols {
		if v.Err != "" || v.SharedWith != "" {
			continue
		}
		if v.Level >= LevelWarning {
			r.Warnings = append(r.Warnings, spaceWarning(v))
		}
		name := v.Name
		perDay, ok := g.rate(now, func(s sample) (int64, bool) { n, ok := s.Volumes[name]; return n, ok })
		if ok && perDay > 0 {
			days := float64(v.Avail) / float64(perDay)
			if days < fillWarnDays {
				r.Warnings = append(r.Warnings, Warning{Kind: WarnGrowth, Detail: fmt.Sprintf(
					"The %s volume grew %s in the last day; at that rate it fills in about %s.", strings.ToLower(v.Label), Bytes(perDay), daysText(days))})
			}
		}
	}
	for _, w := range g.watches() {
		wr := WatchReport{Watch: w}
		if n := len(g.st.Samples); n > 0 {
			wr.Size = g.st.Samples[n-1].Watches[w.Name]
		}
		name := w.Name
		if perDay, ok := g.rate(now, func(s sample) (int64, bool) { n, ok := s.Watches[name]; return n, ok }); ok {
			wr.GrowthPerDay = perDay
		}
		if w.WAL != "" {
			if n, err := g.dirSize(w.WALPath()); err == nil {
				wr.WALSize = n
				if w.WALWarn > 0 && n > w.WALWarn {
					r.Warnings = append(r.Warnings, Warning{Kind: WarnWAL, Detail: fmt.Sprintf(
						"%s's write-ahead log is %s, over its %s limit. The database keeps it in check through its own settings; one that keeps growing means its checkpoints or its archiving are stuck.", w.Label, Bytes(n), Bytes(w.WALWarn))})
				}
			}
		}
		r.Watches = append(r.Watches, wr)
	}
	if g.Archive != nil {
		if a := g.Archive(); a != nil && len(a.Flagged) > 0 {
			r.Warnings = append(r.Warnings, Warning{Kind: WarnAuditArchive, Detail: fmt.Sprintf(
				"The OS audit archive is over its cap: %d closed files (%s, from %s) move to the backup volume after %s UTC. Export the audit log from Logs and audit first to keep a copy elsewhere.",
				len(a.Flagged), Bytes(a.FlaggedBytes), dayOfFile(a.Flagged[0]), a.ExportAfter.UTC().Format("2006-01-02 15:04"))})
		}
	}
	return r
}

func spaceWarning(v VolumeReport) Warning {
	pct := int(v.Percent)
	what := fmt.Sprintf("The %s volume is %d%% full (%s of %s). ", strings.ToLower(v.Label), pct, Bytes(int64(v.Used)), Bytes(int64(v.Used+v.Avail))) // #nosec G115 -- a volume size fits an int64
	if v.Level == LevelCritical {
		return Warning{Kind: WarnSpace, Critical: true, Detail: what + "The box has cleaned up what it may; writes will soon fail. Free space or grow the disk now."}
	}
	return Warning{Kind: WarnSpace, Detail: what + "The box cleans up on its own every hour; if it stays this full, grow the disk."}
}

func daysText(d float64) string {
	if d < 1 {
		return "less than a day"
	}
	if d < 2 {
		return "a day"
	}
	return fmt.Sprintf("%d days", int(d))
}

func dayOfFile(name string) string {
	k := strings.TrimSuffix(strings.TrimPrefix(name, "log-"), ".gz")
	day, _, _ := strings.Cut(k, ".")
	return day
}

// runCommand runs name with args and returns its output, with its error
// output in the error.
func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- the installed bundle's k0s with fixed arguments
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", filepath.Base(name), args[0], err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}
