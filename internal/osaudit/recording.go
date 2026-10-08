// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osaudit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// ChunkSize is how many bytes of a recording each logged hash covers.
const ChunkSize = 64 * 1024

// The audit actions a recording writes.
const (
	ActionRecordingChunk = "recording.chunk"
	ActionRecordingEnd   = "recording.end"
)

// RecordingPath is where request id's session recording lives in the log
// directory dir.
func RecordingPath(dir, id string) string {
	return filepath.Join(dir, SessionsDir, id+".cast")
}

// Appender takes audit entries; *Log is one.
type Appender interface {
	Append(Entry) error
}

// Recorder writes an asciicast v2 recording of a session to w, both
// directions, and appends the SHA-256 of every ChunkSize bytes it wrote to
// the audit log as it goes. A session killed mid-way leaves a recording
// whose logged prefix still verifies.
type Recorder struct {
	w     io.Writer
	log   Appender
	id    string
	name  string
	start time.Time
	now   func() time.Time

	mu     sync.Mutex
	h      hash.Hash
	inBuf  int
	chunks int
	err    error
}

// NewRecorder starts a recording with id (the elevation request id) of
// admin's root shell, named in the audit by admin and start time, and
// writes the asciicast header. Write records output; Input records what the
// admin typed.
func NewRecorder(w io.Writer, log Appender, id, admin string) *Recorder {
	return newRecorder(w, log, id, admin, time.Now, 80, 24)
}

func newRecorder(w io.Writer, log Appender, id, admin string, now func() time.Time, width, height int) *Recorder {
	r := &Recorder{w: w, log: log, id: id, now: now, start: now(), h: sha256.New()}
	r.name = admin + "'s root shell recording, started " + r.start.UTC().Format("2006-01-02 15:04 UTC")
	header, _ := json.Marshal(map[string]any{"version": 2, "width": width, "height": height, "timestamp": r.start.Unix()})
	r.emit(append(header, '\n'))
	return r
}

// Write records p as session output.
func (r *Recorder) Write(p []byte) (int, error) {
	if err := r.event("o", p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Input records p as session input.
func (r *Recorder) Input(p []byte) error { return r.event("i", p) }

func (r *Recorder) event(kind string, p []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	elapsed := r.now().Sub(r.start).Seconds()
	line, err := json.Marshal([]any{elapsed, kind, string(p)})
	if err != nil {
		return err
	}
	r.emit(append(line, '\n'))
	return r.err
}

// emit writes b through and hashes it in ChunkSize pieces. Caller holds mu
// (or is the constructor).
func (r *Recorder) emit(b []byte) {
	if r.err != nil {
		return
	}
	if _, err := r.w.Write(b); err != nil {
		r.err = fmt.Errorf("recording %s: %w", r.id, err)
		return
	}
	for len(b) > 0 {
		n := min(ChunkSize-r.inBuf, len(b))
		r.h.Write(b[:n])
		r.inBuf += n
		b = b[n:]
		if r.inBuf == ChunkSize {
			r.logChunk(false)
		}
	}
}

func (r *Recorder) logChunk(final bool) {
	e := Entry{
		Actor:  "sneakers-elevated",
		Action: ActionRecordingChunk,
		Target: r.name,
		Detail: map[string]string{
			"recording": r.id,
			"n":         strconv.Itoa(r.chunks),
			"bytes":     strconv.Itoa(r.inBuf),
			"sha256":    hex.EncodeToString(r.h.Sum(nil)),
		},
	}
	if final {
		e.Detail["final"] = "true"
	}
	if err := r.log.Append(e); err != nil {
		r.err = fmt.Errorf("recording %s: %w", r.id, err)
		return
	}
	r.chunks++
	r.inBuf = 0
	r.h.Reset()
}

// Close logs the last partial chunk and the end of the recording.
func (r *Recorder) Close(reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	if r.inBuf > 0 {
		r.logChunk(true)
	}
	if r.err != nil {
		return r.err
	}
	return r.log.Append(Entry{Actor: "sneakers-elevated", Action: ActionRecordingEnd, Target: r.name, Outcome: reason,
		Detail: map[string]string{"recording": r.id, "chunks": strconv.Itoa(r.chunks)}})
}

// VerifyRecording checks data, a recording's bytes, against the chunk
// hashes the log holds for id. Every logged chunk must match, in order. A
// recording without its end entry (a killed session) may carry less than one
// chunk of unlogged bytes after the last logged chunk; more than that means
// bytes were added.
func VerifyRecording(data []byte, l *Log, id string) error {
	_, err := VerifyRecordingPrefix(data, l, id)
	return err
}

// VerifyRecordingPrefix is VerifyRecording that also returns how many bytes
// the log covers.
func VerifyRecordingPrefix(data []byte, l *Log, id string) (int, error) {
	entries, err := l.Entries()
	if err != nil {
		return 0, err
	}
	off, n, ended, endChunks := 0, 0, false, -1
	for _, e := range entries {
		if e.Detail["recording"] != id {
			continue
		}
		switch e.Action {
		case ActionRecordingChunk:
			if e.Detail["n"] != strconv.Itoa(n) {
				return off, fmt.Errorf("recording %s: chunk %s logged out of order", id, e.Detail["n"])
			}
			size, err := strconv.Atoi(e.Detail["bytes"])
			if err != nil || size <= 0 || size > ChunkSize {
				return off, fmt.Errorf("recording %s: chunk %d has a bad size", id, n)
			}
			if off+size > len(data) {
				return off, fmt.Errorf("recording %s: chunk %d is logged but the recording is shorter", id, n)
			}
			sum := sha256.Sum256(data[off : off+size])
			if hex.EncodeToString(sum[:]) != e.Detail["sha256"] {
				return off, fmt.Errorf("recording %s: chunk %d doesn't match its logged hash", id, n)
			}
			off += size
			n++
		case ActionRecordingEnd:
			ended = true
			endChunks, _ = strconv.Atoi(e.Detail["chunks"])
		}
	}
	if n == 0 && !bytes.HasPrefix(data, []byte(`{"`)) {
		return 0, fmt.Errorf("recording %s: not an asciicast recording", id)
	}
	if !ended && len(data)-off >= ChunkSize {
		return off, fmt.Errorf("recording %s: more than a chunk of bytes after the last logged chunk", id)
	}
	if ended && (endChunks != n || off != len(data)) {
		return off, fmt.Errorf("recording %s: the recording doesn't end where the log says it does", id)
	}
	return off, nil
}
