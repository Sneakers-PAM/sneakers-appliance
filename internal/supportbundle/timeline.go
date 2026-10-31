// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package supportbundle

import (
	"cmp"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// stampLayout is every normalised time: UTC, to the millisecond, one
// width, so the lines sort as text too.
const stampLayout = "2006-01-02T15:04:05.000Z"

var (
	// A time at the start of a line, after kubectl's --prefix if there is
	// one. kubectl --timestamps, prepare's record and most tools.
	leading = regexp.MustCompile(`^(\[[^\]]*\] )?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s*`)
	// A time in a structured field: JSON, logrus and logfmt.
	field = regexp.MustCompile(`(?:"(?:time|ts|timestamp)"\s*:\s*"?|\b(?:time|ts|timestamp)="?)(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)`)
	// An epoch in a JSON field (zap's ts).
	epoch = regexp.MustCompile(`"(?:ts|time)"\s*:\s*(\d{10}(?:\.\d+)?)[,}]`)
	// klog's Lmmdd hh:mm:ss.uuuuuu, which has no year.
	klog = regexp.MustCompile(`^(?:\[[^\]]*\] )?[IWEF](\d{2})(\d{2}) (\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s`)
	// Go's log package.
	goLog = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s*`)
)

// Stamp finds the time a log line carries, as UTC, and returns the line
// with a leading time taken out, since the bundle writes its own in front.
// A time with no zone is the box's, which runs in UTC.
func Stamp(line string, now time.Time) (time.Time, string, bool) {
	if m := leading.FindStringSubmatch(line); m != nil {
		if t, ok := parseTime(m[2]); ok {
			return t, m[1] + strings.TrimLeft(line[len(m[0]):], " "), true
		}
	}
	if m := field.FindStringSubmatch(line); m != nil {
		if t, ok := parseTime(m[1]); ok {
			return t, line, true
		}
	}
	if m := epoch.FindStringSubmatch(line); m != nil {
		if f, err := strconv.ParseFloat(m[1], 64); err == nil {
			sec, frac := math.Modf(f)
			return time.Unix(int64(sec), int64(frac*1e9)).UTC().Round(time.Millisecond), line, true
		}
	}
	if m := klog.FindStringSubmatch(line); m != nil {
		year := now.UTC().Year()
		if t, ok := parseTime(strconv.Itoa(year) + "-" + m[1] + "-" + m[2] + "T" + m[3]); ok {
			if t.After(now.Add(24 * time.Hour)) {
				t = t.AddDate(-1, 0, 0)
			}
			return t, line, true
		}
	}
	if m := goLog.FindStringSubmatch(line); m != nil {
		if t, err := time.Parse("2006/01/02 15:04:05", m[1]); err == nil {
			return t.UTC(), line[len(m[0]):], true
		}
	}
	return time.Time{}, line, false
}

func parseTime(s string) (time.Time, bool) {
	s = strings.Replace(s, " ", "T", 1)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999Z0700", "2006-01-02T15:04:05.999999999"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

type event struct {
	at     time.Time
	source string
	line   string
}

// timeline holds the newest max events across every log.
type timeline struct {
	max    int
	events []event
}

func (t *timeline) add(at time.Time, source, line string) {
	if t.max <= 0 {
		return
	}
	t.events = append(t.events, event{at, source, line})
	if len(t.events) >= 2*t.max {
		t.trim()
	}
}

func (t *timeline) trim() {
	slices.SortStableFunc(t.events, func(a, b event) int { return cmp.Compare(a.at.UnixNano(), b.at.UnixNano()) })
	if n := len(t.events) - t.max; n > 0 {
		t.events = slices.Delete(t.events, 0, n)
	}
}
