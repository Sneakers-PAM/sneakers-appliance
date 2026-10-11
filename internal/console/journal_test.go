// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package console_test

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/console"
)

var at = time.Date(2026, 10, 10, 20, 34, 5, 123456000, time.UTC)

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p) // #nosec G304 -- the test's own file
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Each line is stamped with the UTC time its first byte was read, the
// colour codes and carriage returns dropped, so the log reads (and cuts to
// a time window) as plain text.
func TestTheJournalStampsEachLine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "log", "console.log")
	j, err := console.OpenJournal(p, 1<<20, 3)
	if err != nil {
		t.Fatal(err)
	}
	j.Record(at, []byte("\x1b[32mservices: started\x1b[0m service=netd\r\nk0s-interim: pre"))
	j.Record(at.Add(time.Second), []byte("pare done\n"))
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	want := "2026-10-10T20:34:05.123456Z services: started service=netd\n" +
		"2026-10-10T20:34:05.123456Z k0s-interim: prepare done\n"
	if got := read(t, p); got != want {
		t.Fatalf("journal:\n%q\nwant\n%q", got, want)
	}
	if fi, err := os.Stat(filepath.Dir(p)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("the log directory: %v %v", fi.Mode(), err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("the log file's mode is %v", fi.Mode())
	}
}

// Past Max the file rolls to .1, .1 to .2 and so on; the oldest past Keep
// is overwritten, so the log never takes more than (Keep+1)*Max bytes.
func TestTheJournalRotatesAndStaysBounded(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "console.log")
	j, err := console.OpenJournal(p, 64, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		j.Record(at, []byte(strings.Repeat(string(rune('a'+i)), 10)+"\n"))
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	names, _ := filepath.Glob(filepath.Join(dir, "console.log*"))
	if len(names) != 3 {
		t.Fatalf("files %v, want console.log, .1 and .2", names)
	}
	var total int64
	for _, n := range names {
		fi, _ := os.Stat(n)
		if fi.Size() > 64 {
			t.Fatalf("%s is %d bytes, past the bound", n, fi.Size())
		}
		total += fi.Size()
	}
	if !strings.Contains(read(t, p), "tttttttttt") {
		t.Fatalf("the newest line isn't in the current file: %q", read(t, p))
	}
	if strings.Contains(read(t, p+".2"), "aaaaaaaaaa") {
		t.Fatal("the oldest lines outlived the bound")
	}
	if !strings.HasSuffix(read(t, p+".1"), "\n") || !strings.HasSuffix(read(t, p+".2"), "\n") {
		t.Fatal("a rolled file ends mid-line")
	}
}

// A boot appends to what the boots before it left.
func TestTheJournalAppendsAcrossBoots(t *testing.T) {
	p := filepath.Join(t.TempDir(), "console.log")
	for i, line := range []string{"first boot\n", "second boot\n"} {
		j, err := console.OpenJournal(p, 1<<20, 3)
		if err != nil {
			t.Fatal(err)
		}
		j.Record(at.Add(time.Duration(i)*time.Hour), []byte(line))
		if err := j.Close(); err != nil {
			t.Fatal(err)
		}
	}
	want := "2026-10-10T20:34:05.123456Z first boot\n2026-10-10T21:34:05.123456Z second boot\n"
	if got := read(t, p); got != want {
		t.Fatalf("journal %q, want %q", got, want)
	}
}

// Close writes a line still waiting for its newline, lets the file go and
// drops what comes after: nothing holds the state volume once it's closed.
func TestAClosedJournalHoldsNoFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "console.log")
	j, err := console.OpenJournal(p, 1<<20, 3)
	if err != nil {
		t.Fatal(err)
	}
	j.Record(at, []byte("power: closing the volumes"))
	if !openHere(t, p) {
		t.Fatal("an open journal holds no descriptor on its file")
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if openHere(t, p) {
		t.Fatal("the closed journal still holds its file")
	}
	j.Record(at, []byte("after\n"))
	if got := read(t, p); got != "2026-10-10T20:34:05.123456Z power: closing the volumes\n" {
		t.Fatalf("journal %q", got)
	}
	if openHere(t, p) {
		t.Fatal("a record after Close opened the file again")
	}
}

// A very long line is cut into lines of a bounded length, so one runaway
// write can't hold the rest back.
func TestTheJournalCutsAVeryLongLine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "console.log")
	j, err := console.OpenJournal(p, 1<<22, 1)
	if err != nil {
		t.Fatal(err)
	}
	j.Record(at, []byte(strings.Repeat("x", console.JournalLineMax+10)))
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(read(t, p), "\n"), "\n")
	if len(lines) != 2 || len(lines[0]) != len("2026-10-10T20:34:05.123456Z ")+console.JournalLineMax {
		t.Fatalf("%d lines, the first %d bytes", len(lines), len(lines[0]))
	}
}

// The mux records every chunk of the shared output, whoever owns the
// consoles; what came before the journal was set (the boot before the
// state volume opened) is kept, bounded, and recorded first.
func TestTheMuxRecordsTheSharedOutputFromTheStart(t *testing.T) {
	vga := newTTY()
	out, outW := io.Pipe()
	m := console.Join(out, io.Discard, []console.Console{{Name: "tty0", RW: vga}}, t.Logf)
	if _, err := io.WriteString(outW, "sneakers-init: phase=normal\n"); err != nil {
		t.Fatal(err)
	}
	waitShows(t, "tty0", vga, "sneakers-init: phase=normal\n")
	p := filepath.Join(t.TempDir(), "console.log")
	j, err := console.OpenJournal(p, 1<<20, 3)
	if err != nil {
		t.Fatal(err)
	}
	m.SetRecord(j)
	owner, ownerW := io.Pipe()
	m.Attach(owner)
	if _, err := io.WriteString(ownerW, "\x1b[H\x1b[2Jdashboard"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(outW, "services: started service=k0s\n"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(readOrEmpty(p), "service=k0s") {
		if time.Now().After(deadline) {
			t.Fatalf("journal %q", readOrEmpty(p))
		}
		time.Sleep(5 * time.Millisecond)
	}
	m.SetRecord(nil)
	if _, err := io.WriteString(outW, "power: rebooting\n"); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	got := read(t, p)
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(lines) != 2 || !strings.HasSuffix(lines[0], " sneakers-init: phase=normal") || !strings.HasSuffix(lines[1], " services: started service=k0s") {
		t.Fatalf("journal %q", got)
	}
	if strings.Contains(got, "dashboard") {
		t.Fatal("the owner's screen went into the journal")
	}
}

func readOrEmpty(p string) string {
	b, _ := os.ReadFile(p) // #nosec G304 -- the test's own file
	return string(b)
}

// openHere reports whether this process holds a descriptor on p.
func openHere(t *testing.T, p string) bool {
	t.Helper()
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("no /proc/self/fd")
	}
	for _, fd := range fds {
		if l, err := os.Readlink(filepath.Join("/proc/self/fd", fd.Name())); err == nil && l == p {
			return true
		}
	}
	return false
}

// The output kept before the journal is bounded; the journal says how
// much of it wasn't kept.
func TestTheEarlyOutputIsBounded(t *testing.T) {
	serial := newTTY()
	out, outW := io.Pipe()
	m := console.Join(out, io.Discard, []console.Console{{Name: "ttyS0", RW: serial}}, t.Logf)
	line := strings.Repeat("y", 1023) + "\n"
	for range console.EarlyMax/len(line) + 8 {
		if _, err := io.WriteString(outW, line); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := io.WriteString(outW, "last\n"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.HasSuffix(serial.shows(), "last\n") {
		if time.Now().After(deadline) {
			t.Fatal("the output didn't reach the console")
		}
		time.Sleep(5 * time.Millisecond)
	}
	p := filepath.Join(t.TempDir(), "console.log")
	j, err := console.OpenJournal(p, 1<<22, 1)
	if err != nil {
		t.Fatal(err)
	}
	m.SetRecord(j)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	got := read(t, p)
	if strings.Count(got, "yyyy\n") != console.EarlyMax/len(line) {
		t.Fatalf("%d early lines kept, want %d", strings.Count(got, "yyyy\n"), console.EarlyMax/len(line))
	}
	if !strings.Contains(got, " console: 8197 bytes of the boot before the state opened weren't kept\n") {
		t.Fatalf("no note of what wasn't kept: %q", got[len(got)-200:])
	}
}
