// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package osaudit is the OS layer's own audit log (spec 2, Section 4.3). The
// program's audit service runs in k0s and may be down exactly when the OS
// layer matters, so the box keeps JSON lines per day, each carrying the
// SHA-256 of the line before it, and the session recordings whose chunk
// hashes are written to the log as they go.
package osaudit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"
	"golang.org/x/sys/unix"
)

// The default retention (Logs and audit page settings).
const (
	DefaultLogRetention       = 400 * 24 * time.Hour
	DefaultRecordingRetention = 90 * 24 * time.Hour
)

const (
	filePrefix = "log-"
	fileSuffix = ".jsonl"
	dayLayout  = "2006-01-02"
	// SessionsDir holds the recordings, inside the log directory.
	SessionsDir = "sessions"
)

// Entry is one audited event.
type Entry struct {
	Time    time.Time `json:"time"`
	Actor   string    `json:"actor"`
	KeyFP   string    `json:"keyFp,omitempty"`
	Source  string    `json:"source,omitempty"`
	Action  string    `json:"action"`
	Target  string    `json:"target,omitempty"`
	Outcome string    `json:"outcome,omitempty"`
	Code    string    `json:"code,omitempty"`
	// Detail holds action-specific fields (a recording chunk's index and
	// hash, a request id).
	Detail map[string]string `json:"detail,omitempty"`
	// Prev is the hex SHA-256 of the previous line, or "" for the first
	// line the log holds.
	Prev string `json:"prev"`
}

// Options tune a log.
type Options struct {
	Now                func() time.Time
	LogRetention       time.Duration
	RecordingRetention time.Duration
	// MaxFileSize is the size a file rolls over at to the day's next part;
	// 0 is DefaultMaxFileSize.
	MaxFileSize int64
	Logger      log.Logger
}

// Log is the chained log in one directory.
type Log struct {
	dir  string
	o    Options
	mu   sync.Mutex
	head string
	// newest is the newest day file. A clock stepped back (an NTP
	// correction) keeps appending there, so the files stay in chain order.
	newest string
	// size is newest's length after this process's last append or read; a
	// different length means another process (init and osadmin both
	// write) appended since, so the head is read again.
	size int64
}

// lockName is the file every writer holds an flock on while it appends.
const lockName = ".lock"

// Open opens the log in dir, creating it, and finds the chain's head.
func Open(dir string, o Options) (*Log, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.LogRetention == 0 {
		o.LogRetention = DefaultLogRetention
	}
	if o.RecordingRetention == 0 {
		o.RecordingRetention = DefaultRecordingRetention
	}
	if o.Logger == nil {
		o.Logger = log.Nop()
	}
	if o.MaxFileSize <= 0 {
		o.MaxFileSize = DefaultMaxFileSize
	}
	if err := os.MkdirAll(filepath.Join(dir, SessionsDir), 0o700); err != nil {
		return nil, fmt.Errorf("os audit: %w", err)
	}
	l := &Log{dir: dir, o: o}
	files, err := l.files()
	if err != nil {
		return nil, err
	}
	if len(files) > 0 {
		last, err := l.lastLine(files[len(files)-1])
		if err != nil {
			return nil, err
		}
		if last != nil {
			l.head = hashLine(last)
		}
		l.newest = files[len(files)-1]
		l.size = fileSize(filepath.Join(dir, l.newest))
	}
	return l, nil
}

// Dir is the log directory.
func (l *Log) Dir() string { return l.dir }

// Path is the file the next entry goes to.
func (l *Log) Path() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	name, _ := l.target(l.o.Now())
	return filepath.Join(l.dir, name)
}

func (l *Log) pathFor(t time.Time) string {
	return filepath.Join(l.dir, filePrefix+t.UTC().Format(dayLayout)+fileSuffix)
}

// Append writes e as the next line, chained to the one before, and fsyncs
// it before returning.
func (l *Log) Append(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	unlock, err := l.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if err := l.refresh(); err != nil {
		return err
	}
	return l.appendLocked(e)
}

// appendLocked appends e, rolling over to the day's next part first when
// the newest file is full; the caller holds the locks.
func (l *Log) appendLocked(e Entry) error {
	if e.Time.IsZero() {
		e.Time = l.o.Now()
	}
	e.Time = e.Time.UTC()
	name, rolled := l.target(e.Time)
	if rolled {
		if err := l.writeLink(name, e.Time); err != nil {
			return err
		}
	}
	return l.appendTo(name, e)
}

// appendTo writes e to the file name as the next line; the caller holds
// the locks.
func (l *Log) appendTo(name string, e Entry) error {
	e.Prev = l.head
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("os audit: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(l.dir, name), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) // #nosec G304 -- a day file in the log directory
	if err != nil {
		return fmt.Errorf("os audit: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return fmt.Errorf("os audit: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("os audit: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("os audit: %w", err)
	}
	l.head = hashLine(line)
	l.newest = name
	l.size = fileSize(filepath.Join(l.dir, name))
	l.o.Logger.Debug("os audit: appended", log.F("action", e.Action), log.F("actor", e.Actor), log.F("outcome", e.Outcome))
	return nil
}

// Head is the hash of the newest line (what a forwarder records as the last
// one sent).
func (l *Log) Head() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.head
}

// Verify walks every line in order and checks each one's prev against the
// line before. The oldest line left after retention pruning anchors the
// chain.
func (l *Log) Verify() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err := l.walk(func(string, int, Entry) error { return nil })
	return err
}

// Entries returns every entry, oldest first.
func (l *Log) Entries() ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Entry
	_, err := l.walk(func(_ string, _ int, e Entry) error { out = append(out, e); return nil })
	return out, err
}

func (l *Log) walk(fn func(file string, n int, e Entry) error) (string, error) {
	files, err := l.files()
	if err != nil {
		return "", err
	}
	prev, first := "", true
	seen := map[string]fileSum{}
	for _, name := range files {
		b, err := l.readFile(name)
		if err != nil {
			return "", err
		}
		for n, line := range bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n")) {
			if len(line) == 0 {
				return "", fmt.Errorf("os audit: %s line %d is empty", name, n+1)
			}
			var e Entry
			if err := json.Unmarshal(line, &e); err != nil {
				return "", fmt.Errorf("os audit: %s line %d doesn't parse: %w", name, n+1, err)
			}
			if !first && e.Prev != prev {
				return "", fmt.Errorf("os audit: %s line %d doesn't chain to the line before it", name, n+1)
			}
			if n == 0 && e.Action == ActionRotate {
				if err := checkLink(name, e, seen); err != nil {
					return "", err
				}
			}
			first = false
			prev = hashLine(line)
			if err := fn(name, n+1, e); err != nil {
				return "", err
			}
		}
		seen[keyOf(name)] = sumOf(b)
	}
	return prev, nil
}

// SetRetention changes how long log files and recordings are kept.
func (l *Log) SetRetention(logs, recordings time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.o.LogRetention, l.o.RecordingRetention = logs, recordings
}

// Prune removes log files whose day is older than the log retention and
// recordings older than the recording retention.
func (l *Log) Prune() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.o.Now()
	files, err := l.files()
	if err != nil {
		return err
	}
	cut := now.Add(-l.o.LogRetention).UTC().Format(dayLayout)
	for _, name := range files {
		if dayOf(name) < cut && name != l.newest {
			if err := os.Remove(filepath.Join(l.dir, name)); err != nil {
				return fmt.Errorf("os audit: %w", err)
			}
			if name == keyOf(name) {
				_ = os.Remove(filepath.Join(l.dir, name+gzSuffix))
			}
			l.o.Logger.Info("os audit: pruned log file", log.F("file", name))
		}
	}
	sessions, err := os.ReadDir(filepath.Join(l.dir, SessionsDir))
	if err != nil {
		return fmt.Errorf("os audit: %w", err)
	}
	for _, s := range sessions {
		fi, err := s.Info()
		if err != nil {
			return fmt.Errorf("os audit: %w", err)
		}
		if fi.ModTime().Before(now.Add(-l.o.RecordingRetention)) {
			if err := os.Remove(filepath.Join(l.dir, SessionsDir, s.Name())); err != nil {
				return fmt.Errorf("os audit: %w", err)
			}
			l.o.Logger.Info("os audit: pruned recording", log.F("file", s.Name()))
		}
	}
	return nil
}

// RunRetention prunes now and then every interval (a day on the box) until
// ctx ends. A failed prune is logged and retried at the next tick.
func (l *Log) RunRetention(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := l.Prune(); err != nil {
			l.o.Logger.Error(err, "os audit: prune failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// files lists the log's files in chain order: by name with any .gz left
// off, a day's parts after its first file. A file there both plain and
// compressed (a compress cut off before the plain one went) is read
// plain.
func (l *Log) files() ([]string, error) {
	ents, err := os.ReadDir(l.dir)
	if err != nil {
		return nil, fmt.Errorf("os audit: %w", err)
	}
	byKey := map[string]string{}
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasPrefix(n, filePrefix) {
			continue
		}
		k := keyOf(n)
		if !strings.HasSuffix(k, fileSuffix) {
			continue
		}
		if have, ok := byKey[k]; ok && have == k {
			continue
		}
		byKey[k] = n
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, byKey[k])
	}
	return out, nil
}

// lastLine is the last non-empty line of the file name in the log
// directory, or nil when it has none or isn't there.
func (l *Log) lastLine(name string) ([]byte, error) {
	if strings.HasSuffix(name, gzSuffix) {
		b, err := l.readFile(name)
		if err != nil {
			return nil, err
		}
		lines := bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n"))
		if last := lines[len(lines)-1]; len(last) > 0 {
			return last, nil
		}
		return nil, nil
	}
	f, err := os.Open(filepath.Join(l.dir, name)) // #nosec G304 -- the newest file in the log directory
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("os audit: %w", err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	var last []byte
	for sc.Scan() {
		if len(sc.Bytes()) > 0 {
			last = append(last[:0], sc.Bytes()...)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("os audit: %w", err)
	}
	return last, nil
}

// lock takes the writers' flock on the log directory.
func (l *Log) lock() (func(), error) {
	f, err := os.OpenFile(filepath.Join(l.dir, lockName), os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- the lock file in the log directory
	if err != nil {
		return nil, fmt.Errorf("os audit: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil { // #nosec G115 -- a descriptor fits an int
		_ = f.Close()
		return nil, fmt.Errorf("os audit: lock: %w", err)
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN) // #nosec G115 -- as above
		_ = f.Close()
	}, nil
}

// refresh reads the head again when another writer has appended since.
func (l *Log) refresh() error {
	files, err := l.files()
	if err != nil || len(files) == 0 {
		return err
	}
	newest := files[len(files)-1]
	if keyOf(newest) < keyOf(l.newest) {
		newest = l.newest
	}
	size := fileSize(filepath.Join(l.dir, newest))
	if newest == l.newest && size == l.size {
		return nil
	}
	last, err := l.lastLine(newest)
	if err != nil {
		return err
	}
	if last != nil {
		l.head = hashLine(last)
	}
	l.newest, l.size = newest, size
	l.o.Logger.Debug("os audit: another writer appended; head read again", log.F("file", newest))
	return nil
}

func fileSize(p string) int64 {
	st, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return st.Size()
}

func hashLine(line []byte) string {
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}
