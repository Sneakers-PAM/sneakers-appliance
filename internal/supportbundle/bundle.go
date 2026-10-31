// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package supportbundle writes the box's support bundle: a fixed, versioned
// set of read-only commands run one after the other into one plain-text
// file, under one UTC timeline, with every line redacted before it's
// written (docs/support-bundle.md is the format). The base owns the
// runner, the format, the redaction and its own sections (base.go); a
// product adds its sections in product.yaml's support list, and the base
// names none of them.
package supportbundle

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// Format is the bundle format's version; a change a reader must know about
// bumps it (docs/support-bundle.md).
const Format = 1

// Form is how much a bundle holds.
type Form string

// The two forms: Short is the key sections with short tails, to paste from
// a terminal; Full is every section.
const (
	Short Form = "short"
	Full  Form = "full"
)

const (
	// DefaultTimeout bounds a section that sets none.
	DefaultTimeout = 20 * time.Second
	// maxLine is the longest line kept. A longer one is withheld whole: a
	// line cut to size could hide what redaction needs to see.
	maxLine = 64 << 10
	// maxEventLine bounds a timeline line.
	maxEventLine = 400
)

// Section is one numbered section. Its Run writes through the bundle's
// redaction; there's no other way into the file.
type Section struct {
	// Command is what the heading shows.
	Command string
	// Product puts it under the "Product: <name>" heading.
	Product bool
	// Log, when set, says its lines are a log: each is rewritten with its
	// time in UTC and enters the merged timeline, under this source.
	Log string
	// Timeout bounds the section; zero is DefaultTimeout.
	Timeout time.Duration
	// Tail keeps only its last lines; zero keeps them all.
	Tail int
	// Optional says a failure means there's nothing there, such as a log
	// that hasn't rotated yet.
	Optional bool
	// Redact are the section's own extra patterns.
	Redact []*regexp.Regexp
	// Run writes the section.
	Run func(ctx context.Context, w io.Writer) error
}

// Options are one bundle's settings. A zero limit is the form's own.
type Options struct {
	Form Form
	// Box, Version and Product head the file; Product also heads the
	// product's sections.
	Box, Version, Product string
	// Known are values the box knows are secret, masked wherever they
	// appear.
	Known []string
	// Now is the clock, time.Now when nil.
	Now func() time.Time
	// SectionBytes and TotalBytes bound the output, Deadline the whole
	// run; TimelineLines are the newest lines the timeline keeps.
	SectionBytes, TotalBytes int64
	Deadline                 time.Duration
	TimelineLines            int
}

func (o Options) withDefaults() Options {
	if o.Now == nil {
		o.Now = time.Now
	}
	def := Options{SectionBytes: 32 << 20, TotalBytes: 200 << 20, Deadline: 10 * time.Minute, TimelineLines: 5000}
	if o.Form == Short {
		def = Options{SectionBytes: 256 << 10, TotalBytes: 4 << 20, Deadline: 2 * time.Minute, TimelineLines: 50}
	}
	if o.SectionBytes == 0 {
		o.SectionBytes = def.SectionBytes
	}
	if o.TotalBytes == 0 {
		o.TotalBytes = def.TotalBytes
	}
	if o.Deadline == 0 {
		o.Deadline = def.Deadline
	}
	if o.TimelineLines == 0 {
		o.TimelineLines = def.TimelineLines
	}
	return o
}

// Report says what a bundle came to, for the audit entry.
type Report struct {
	Sections, Failed, Truncated int
	Bytes                       int64
}

type bundle struct {
	o        Options
	w        *bufio.Writer
	raw      io.Writer
	timeline timeline
	report   Report
	err      error
}

func (b *bundle) stamp() string { return b.o.Now().UTC().Format(time.RFC3339) }

func (b *bundle) print(line string) {
	if b.err != nil {
		return
	}
	n, err := b.w.WriteString(line + "\n")
	b.report.Bytes += int64(n)
	b.err = err
}

// flush sends what's written on; a download or a terminal sees each
// section as it ends.
func (b *bundle) flush() {
	if b.err != nil {
		return
	}
	if b.err = b.w.Flush(); b.err != nil {
		return
	}
	if f, ok := b.raw.(interface{ Flush() }); ok {
		f.Flush()
	}
}

// Write runs sections in order into w. A section that fails is noted and
// the next one runs; only a writer that fails, the reader having gone,
// ends the bundle early.
func Write(ctx context.Context, w io.Writer, o Options, sections []Section) (Report, error) {
	o = o.withDefaults()
	b := &bundle{o: o, w: bufio.NewWriterSize(w, 32<<10), raw: w, timeline: timeline{max: o.TimelineLines}}
	ctx, cancel := context.WithTimeout(ctx, o.Deadline)
	defer cancel()

	b.print("##### support-bundle")
	b.print(fmt.Sprintf("bundle-format: %d", Format))
	b.print("form: " + string(o.Form))
	if o.Box != "" {
		b.print("box: " + printable(o.Box))
	}
	if o.Version != "" {
		b.print("version: " + printable(o.Version))
	}
	if o.Product != "" {
		b.print("product: " + printable(o.Product))
	}
	b.print("started: " + b.stamp())
	b.print("")
	b.flush()

	product := false
	n := 0
	for _, s := range sections {
		if s.Product && !product {
			product = true
			b.print("==== Product: " + printable(o.Product) + " ====")
			b.print("")
		}
		n++
		b.section(ctx, n, s)
		if b.err != nil {
			return b.report, b.err
		}
	}
	n++
	b.writeTimeline(n)
	b.report.Sections = n
	b.print(fmt.Sprintf("##### end sections=%d failed=%d truncated=%d", n, b.report.Failed, b.report.Truncated))
	b.flush()
	return b.report, b.err
}

func (b *bundle) section(ctx context.Context, n int, s Section) {
	b.print(fmt.Sprintf("##### %d. %s", n, printable(s.Command)))
	limit := min(b.o.SectionBytes, b.o.TotalBytes-b.report.Bytes)
	switch {
	case ctx.Err() != nil:
		b.print("# skipped: the bundle's time limit")
		b.print("")
		b.report.Truncated++
		return
	case limit <= 0:
		b.print("# skipped: the bundle's size limit")
		b.print("")
		b.report.Truncated++
		return
	}
	b.print("# started: " + b.stamp())
	timeout := s.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	sctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	red := NewRedactor(b.o.Known, s.Redact)
	sink := &sink{b: b, s: s, red: red, limit: limit, stop: cancel}
	err := s.Run(sctx, sink)
	sink.finish()
	if b.err != nil {
		return
	}
	result := "ok"
	switch {
	case sink.cut:
		result = fmt.Sprintf("truncated at %d bytes", limit)
		b.report.Truncated++
	case err == nil:
	case s.Optional:
		result = "absent"
	case errors.Is(sctx.Err(), context.DeadlineExceeded):
		result = "timed out after " + timeout.String()
		b.report.Failed++
	default:
		msg, _ := red.Line(strings.ReplaceAll(err.Error(), "\n", " "))
		result = "failed: " + msg
		b.report.Failed++
	}
	b.print("# ended: " + b.stamp() + " result: " + result)
	b.print("")
	b.flush()
}

func (b *bundle) writeTimeline(n int) {
	b.print(fmt.Sprintf("##### %d. timeline", n))
	b.print("# started: " + b.stamp())
	b.timeline.trim()
	for _, e := range b.timeline.events {
		line := e.line
		if len(line) > maxEventLine {
			line = strings.ToValidUTF8(line[:maxEventLine], "") + " [cut]"
		}
		b.print(e.at.Format(stampLayout) + " [" + e.source + "] " + line)
	}
	b.print("# ended: " + b.stamp() + " result: ok")
	b.print("")
}

// sink is a section's way into the file: it takes the section's bytes,
// makes them lines and passes each through the section's redactor.
type sink struct {
	b     *bundle
	s     Section
	red   *Redactor
	limit int64
	stop  context.CancelFunc

	partial []byte
	// tooLong is true while a line past maxLine goes by.
	tooLong bool
	tail    []string
	written int64
	cut     bool
}

// Write never fails for its section's sake, or a command would stop on a
// section that's only been cut; a reader that's gone stops it.
func (s *sink) Write(p []byte) (int, error) {
	if s.b.err != nil {
		return 0, s.b.err
	}
	n := len(p)
	for len(p) > 0 {
		i := indexNewline(p)
		if i < 0 {
			s.keep(p)
			break
		}
		s.keep(p[:i])
		p = p[i+1:]
		s.endLine()
	}
	return n, s.b.err
}

func indexNewline(p []byte) int {
	for i, c := range p {
		if c == '\n' {
			return i
		}
	}
	return -1
}

func (s *sink) keep(p []byte) {
	if s.tooLong {
		return
	}
	if len(s.partial)+len(p) > maxLine {
		s.partial, s.tooLong = s.partial[:0], true
		return
	}
	s.partial = append(s.partial, p...)
}

func (s *sink) endLine() {
	line := string(s.partial)
	s.partial = s.partial[:0]
	if s.tooLong {
		s.tooLong = false
		s.line(fmt.Sprintf("[a line over %d bytes was withheld]", maxLine))
		return
	}
	s.line(strings.TrimSuffix(line, "\r"))
}

func (s *sink) line(raw string) {
	line, ok := s.red.Line(raw)
	if !ok {
		return
	}
	if s.s.Log != "" {
		if at, rest, ok := Stamp(line, s.b.o.Now()); ok {
			line = at.Format(stampLayout) + " " + rest
			s.b.timeline.add(at, s.s.Log, rest)
		}
	}
	if s.s.Tail > 0 {
		s.tail = append(s.tail, line)
		if len(s.tail) > 2*s.s.Tail {
			s.tail = append(s.tail[:0], s.tail[len(s.tail)-s.s.Tail:]...)
		}
		return
	}
	s.emit(line)
}

func (s *sink) emit(line string) {
	if s.cut {
		return
	}
	if s.written+int64(len(line))+1 > s.limit {
		s.cut = true
		s.stop()
		return
	}
	s.written += int64(len(line)) + 1
	s.b.print(line)
}

// finish writes what's left: a last line with no newline and a tail.
func (s *sink) finish() {
	if len(s.partial) > 0 || s.tooLong {
		s.endLine()
	}
	if s.s.Tail > 0 {
		for _, l := range s.tail[max(0, len(s.tail)-s.s.Tail):] {
			s.emit(l)
		}
	}
}
