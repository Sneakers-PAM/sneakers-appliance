// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package console

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// Recorder keeps the shared output with the time each chunk was read.
type Recorder interface {
	Record(t time.Time, chunk []byte)
}

// JournalLineMax bounds one journal line; a longer one is cut into lines
// of this length.
const JournalLineMax = 16 << 10

// JournalTime is the layout of each line's stamp: UTC, microseconds, fixed
// width, so the lines sort and line up.
const JournalTime = "2006-01-02T15:04:05.000000Z"

// escapes are the terminal's colour and cursor codes, dropped from the
// journal so it reads as text.
var escapes = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][0-9A-Za-z]|\x1b[=>78]`)

// Journal is init's persistent console log on the state volume: every line
// of the shared output, stamped with the UTC time its first byte was read
// (JournalTime, then a space), appended to Path. Past Max bytes the file
// rolls to Path.1, Path.1 to Path.2 and so on, Keep files back; the oldest
// is overwritten, so the journal never takes more than (Keep+1)*Max bytes.
// Close lets the file go before the volume is unmounted; a closed journal
// drops what it's given.
type Journal struct {
	path string
	max  int64
	keep int

	mu      sync.Mutex
	f       *os.File
	size    int64
	line    []byte
	lineAt  time.Time
	closed  bool
	lastErr error
}

// OpenJournal opens (or creates, with its directory) the journal at path,
// to append to what earlier boots left.
func OpenJournal(path string, max int64, keep int) (*Journal, error) {
	if max <= 0 || keep < 1 {
		return nil, errors.New("console: a journal needs a size bound and at least one older file")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("console: the journal's directory: %w", err)
	}
	j := &Journal{path: path, max: max, keep: keep}
	if err := j.open(); err != nil {
		return nil, err
	}
	return j, nil
}

func (j *Journal) open() error {
	f, err := os.OpenFile(j.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("console: the journal: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("console: the journal: %w", err)
	}
	j.f, j.size = f, st.Size()
	return nil
}

// Record adds chunk, read at t. Complete lines are written at once; the
// rest waits for its newline (or Close).
func (j *Journal) Record(t time.Time, chunk []byte) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return
	}
	for _, b := range chunk {
		if len(j.line) == 0 {
			j.lineAt = t
		}
		if b == '\n' {
			j.flushLine()
			continue
		}
		j.line = append(j.line, b)
		if len(j.line) >= JournalLineMax+64 {
			j.flushLine()
		}
	}
}

// flushLine writes the pending line, cleaned and stamped.
func (j *Journal) flushLine() {
	text := escapes.ReplaceAll(j.line, nil)
	j.line = j.line[:0]
	clean := text[:0]
	for _, b := range text {
		if b != '\r' {
			clean = append(clean, b)
		}
	}
	for len(clean) > JournalLineMax {
		j.write(clean[:JournalLineMax])
		clean = clean[JournalLineMax:]
	}
	j.write(clean)
}

func (j *Journal) write(text []byte) {
	out := make([]byte, 0, len(JournalTime)+2+len(text))
	out = j.lineAt.UTC().AppendFormat(out, JournalTime)
	out = append(out, ' ')
	out = append(out, text...)
	out = append(out, '\n')
	if j.f != nil && j.size > 0 && j.size+int64(len(out)) > j.max {
		j.rotate()
	}
	if j.f == nil {
		if err := j.open(); err != nil {
			j.lastErr = err
			return
		}
	}
	n, err := j.f.Write(out)
	j.size += int64(n)
	if err != nil {
		// The next line opens the file again.
		j.lastErr = err
		_ = j.f.Close()
		j.f = nil
	}
}

// rotate rolls the files one back: the oldest kept one is overwritten.
func (j *Journal) rotate() {
	_ = j.f.Close()
	j.f = nil
	for i := j.keep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", j.path, i), fmt.Sprintf("%s.%d", j.path, i+1))
	}
	_ = os.Rename(j.path, j.path+".1")
}

// Close writes a line still waiting for its newline and closes the file;
// what comes later is dropped. It returns the last write error, if any.
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	if len(j.line) > 0 {
		j.flushLine()
	}
	j.closed = true
	if j.f == nil {
		return j.lastErr
	}
	err := j.f.Close()
	j.f = nil
	return errors.Join(j.lastErr, err)
}
