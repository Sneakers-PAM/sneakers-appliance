// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osaudit_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func openLog(t *testing.T) *osaudit.Log {
	t.Helper()
	l, err := osaudit.Open(t.TempDir(), osaudit.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func flipByteInLine(t *testing.T, path string, line int) {
	t.Helper()
	b, err := os.ReadFile(path)
	mustNoErr(t, err)
	lines := bytes.Split(b, []byte("\n"))
	l := lines[line-1]
	i := bytes.Index(l, []byte(`"action":"a`)) + len(`"action":"a`)
	l[i] ^= 0x01 // "a1" becomes "a0": still valid JSON, different content
	mustNoErr(t, os.WriteFile(path, bytes.Join(lines, []byte("\n")), 0o600))
}

func TestChainVerifies(t *testing.T) {
	l := openLog(t)
	for i := range 3 {
		mustNoErr(t, l.Append(osaudit.Entry{Actor: "alice", Action: fmt.Sprintf("a%d", i)}))
	}
	mustNoErr(t, l.Verify())
}

func TestChainTamperDetected(t *testing.T) {
	l := openLog(t)
	for i := range 3 {
		mustNoErr(t, l.Append(osaudit.Entry{Actor: "alice", Action: fmt.Sprintf("a%d", i)}))
	}
	flipByteInLine(t, l.Path(), 2)
	if err := l.Verify(); err == nil {
		t.Fatal("a changed line verified")
	}
}

func TestDeletedLineDetected(t *testing.T) {
	l := openLog(t)
	for i := range 3 {
		mustNoErr(t, l.Append(osaudit.Entry{Actor: "alice", Action: fmt.Sprintf("a%d", i)}))
	}
	b, _ := os.ReadFile(l.Path())
	lines := bytes.SplitAfter(b, []byte("\n"))
	mustNoErr(t, os.WriteFile(l.Path(), append(append([]byte{}, lines[0]...), lines[2]...), 0o600))
	if err := l.Verify(); err == nil {
		t.Fatal("a deleted line verified")
	}
}

func TestChainContinuesAcrossDaysAndReopen(t *testing.T) {
	dir := t.TempDir()
	clk := &fakeClock{t: time.Date(2026, 10, 5, 23, 59, 0, 0, time.UTC)}
	l, err := osaudit.Open(dir, osaudit.Options{Now: clk.Now})
	mustNoErr(t, err)
	mustNoErr(t, l.Append(osaudit.Entry{Actor: "console", Action: "a0"}))
	clk.Advance(2 * time.Minute)
	mustNoErr(t, l.Append(osaudit.Entry{Actor: "console", Action: "a1"}))
	head := l.Head()
	l2, err := osaudit.Open(dir, osaudit.Options{Now: clk.Now})
	mustNoErr(t, err)
	if l2.Head() != head {
		t.Fatal("reopen lost the chain head")
	}
	mustNoErr(t, l2.Append(osaudit.Entry{Actor: "console", Action: "a2"}))
	mustNoErr(t, l2.Verify())
	files, _ := filepath.Glob(filepath.Join(dir, "log-*.jsonl"))
	if len(files) != 2 {
		t.Fatalf("files %v, want one per day", files)
	}
}

// A clock stepped back a day (an NTP correction on a box that booted hours
// off) keeps writing to the newest file, so the chain still verifies.
func TestClockSteppedBackKeepsChain(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 10, 7, 1, 0, 0, 0, time.UTC)}
	l, err := osaudit.Open(t.TempDir(), osaudit.Options{Now: clk.Now})
	mustNoErr(t, err)
	mustNoErr(t, l.Append(osaudit.Entry{Actor: "console", Action: "a0"}))
	clk.Advance(-26 * time.Hour)
	mustNoErr(t, l.Append(osaudit.Entry{Actor: "console", Action: "a1"}))
	mustNoErr(t, l.Verify())
	es, err := l.Entries()
	mustNoErr(t, err)
	if len(es) != 2 || es[1].Action != "a1" {
		t.Fatalf("entries %+v", es)
	}
}

func TestRetention(t *testing.T) {
	dir := t.TempDir()
	clk := &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	l, err := osaudit.Open(dir, osaudit.Options{Now: clk.Now, ArchiveDir: t.TempDir()})
	mustNoErr(t, err)
	mustNoErr(t, l.Append(osaudit.Entry{Actor: "console", Action: "old"}))
	oldRec := filepath.Join(dir, osaudit.SessionsDir, "E-OLD1.cast")
	mustNoErr(t, os.WriteFile(oldRec, []byte("{}\n"), 0o600))
	mustNoErr(t, os.Chtimes(oldRec, clk.t, clk.t))

	clk.Advance(91 * 24 * time.Hour)
	mustNoErr(t, l.Append(osaudit.Entry{Actor: "console", Action: "new"}))
	mustNoErr(t, l.Prune())
	if _, err := os.Stat(oldRec); !os.IsNotExist(err) {
		t.Fatal("a 91-day-old recording survived the 90-day default")
	}
	if es, _ := l.Entries(); len(es) != 2 {
		t.Fatalf("a 91-day-old log file was pruned under the 400-day default: %d entries", len(es))
	}

	l.SetRetention(30*24*time.Hour, 90*24*time.Hour)
	mustNoErr(t, l.Prune())
	es, err := l.Entries()
	mustNoErr(t, err)
	// The pruned file went to the archive first, and its removal is an
	// entry of its own.
	if len(es) != 2 || es[0].Action != "new" || es[1].Action != osaudit.ActionPrune {
		t.Fatalf("after a 30-day retention: %+v", es)
	}
	mustNoErr(t, l.Verify())
}

func TestRunRetentionPrunes(t *testing.T) {
	dir := t.TempDir()
	clk := &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	l, err := osaudit.Open(dir, osaudit.Options{Now: clk.Now})
	mustNoErr(t, err)
	rec := filepath.Join(dir, osaudit.SessionsDir, "E-OLD2.cast")
	mustNoErr(t, os.WriteFile(rec, []byte("{}\n"), 0o600))
	old := time.Now().Add(-100 * 24 * time.Hour)
	mustNoErr(t, os.Chtimes(rec, old, old))
	clk.t = time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { l.RunRetention(ctx, time.Hour); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(rec); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("RunRetention didn't prune on start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}

// Init and osadmin each hold the log open; their appends must keep one
// chain.
func TestTwoWritersKeepOneChain(t *testing.T) {
	dir := t.TempDir()
	a, err := osaudit.Open(dir, osaudit.Options{})
	mustNoErr(t, err)
	b, err := osaudit.Open(dir, osaudit.Options{})
	mustNoErr(t, err)
	for i := range 4 {
		w := a
		if i%2 == 1 {
			w = b
		}
		mustNoErr(t, w.Append(osaudit.Entry{Actor: "alice", Action: fmt.Sprintf("a%d", i)}))
	}
	mustNoErr(t, a.Verify())
	got, err := b.Entries()
	mustNoErr(t, err)
	if len(got) != 4 {
		t.Fatalf("%d entries", len(got))
	}
}
