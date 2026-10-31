// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package supportbundle

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

var testNow = time.Date(2026, 10, 30, 16, 0, 0, 0, time.UTC)

func clockFrom(t time.Time) func() time.Time {
	return func() time.Time {
		t = t.Add(time.Second)
		return t
	}
}

func text(lines ...string) func(context.Context, io.Writer) error {
	return func(_ context.Context, w io.Writer) error {
		_, err := io.WriteString(w, strings.Join(lines, "\n")+"\n")
		return err
	}
}

func write(t *testing.T, o Options, sections ...Section) (string, Report) {
	t.Helper()
	if o.Now == nil {
		o.Now = clockFrom(testNow)
	}
	if o.Form == "" {
		o.Form = Full
	}
	var b bytes.Buffer
	r, err := Write(context.Background(), &b, o, sections)
	if err != nil {
		t.Fatal(err)
	}
	return b.String(), r
}

func TestStamp(t *testing.T) {
	cases := map[string]struct {
		line, want, rest string
	}{
		"rfc3339 utc":    {"2026-10-30T12:00:01Z k0s-interim: prepare starts", "2026-10-30T12:00:01Z", "k0s-interim: prepare starts"},
		"rfc3339 nanos":  {"2026-10-30T12:00:01.123456789Z hello", "2026-10-30T12:00:01.123456789Z", "hello"},
		"rfc3339 offset": {"2026-10-30T08:00:01-04:00 hello", "2026-10-30T12:00:01Z", "hello"},
		"kubectl prefix": {"[pod/x/c] 2026-10-30T12:00:01.5Z hello", "2026-10-30T12:00:01.5Z", "[pod/x/c] hello"},
		"json time":      {`{"level":"error","time":"2026-10-30T08:00:01-04:00","msg":"x"}`, "2026-10-30T12:00:01Z", `{"level":"error","time":"2026-10-30T08:00:01-04:00","msg":"x"}`},
		"json ts epoch":  {`{"ts":1793448001.5,"msg":"x"}`, "2026-10-31T12:00:01.5Z", `{"ts":1793448001.5,"msg":"x"}`},
		"logrus":         {`time="2026-10-30 12:00:01" level=info msg="x"`, "2026-10-30T12:00:01Z", `time="2026-10-30 12:00:01" level=info msg="x"`},
		"logfmt ts":      {`ts=2026-10-30T12:00:01.000Z caller=x`, "2026-10-30T12:00:01Z", `ts=2026-10-30T12:00:01.000Z caller=x`},
		"klog":           {"E1030 12:00:01.250000    4242 kubelet.go:1] failed", "2026-10-30T12:00:01.25Z", "E1030 12:00:01.250000    4242 kubelet.go:1] failed"},
		"go log":         {"2026/10/30 12:00:01 starting", "2026-10-30T12:00:01Z", "starting"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, rest, ok := Stamp(c.line, testNow)
			if !ok {
				t.Fatal("no time found")
			}
			want, err := time.Parse(time.RFC3339Nano, c.want)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Equal(want) || rest != c.rest {
				t.Fatalf("got %s %q, want %s %q", got, rest, want, c.rest)
			}
		})
	}
	for _, line := range []string{"", "no time in this line", "12:00:01 a time alone"} {
		if _, _, ok := Stamp(line, testNow); ok {
			t.Fatalf("%q has no time", line)
		}
	}
}

// klog has no year: the last December's lines read in January of the next.
func TestStampKlogAcrossNewYear(t *testing.T) {
	got, _, ok := Stamp("I1231 23:59:59.000000 1 x.go:1] bye", time.Date(2027, 1, 1, 0, 0, 5, 0, time.UTC))
	if !ok || got.Year() != 2026 {
		t.Fatalf("got %s", got)
	}
}

// The heading and timing lines are the format #388 reads: docs/support-bundle.md.
func TestTheFormat(t *testing.T) {
	out, r := write(t, Options{Box: "box1", Version: "0.1.0"},
		Section{Command: "first command", Run: text("hello")},
		Section{Command: "second command", Run: text("world")},
	)
	want := []string{
		"##### support-bundle",
		"bundle-format: 1",
		"form: full",
		"box: box1",
		"version: 0.1.0",
		"started: 2026-10-30T16:00:01Z",
		"",
		"##### 1. first command",
		"# started: 2026-10-30T16:00:02Z",
		"hello",
		"# ended: 2026-10-30T16:00:03Z result: ok",
		"",
		"##### 2. second command",
		"# started: 2026-10-30T16:00:04Z",
		"world",
		"# ended: 2026-10-30T16:00:05Z result: ok",
		"",
		"##### 3. timeline",
		"# started: 2026-10-30T16:00:06Z",
		"# ended: 2026-10-30T16:00:07Z result: ok",
		"",
		"##### end sections=3 failed=0 truncated=0",
	}
	if got := strings.Split(strings.TrimRight(out, "\n"), "\n"); !slices.Equal(got, want) {
		t.Fatalf("got:\n%s", out)
	}
	if r.Sections != 3 || r.Failed != 0 {
		t.Fatalf("report %+v", r)
	}
}

func TestLogsAreNormalisedAndMergedIntoOneTimeline(t *testing.T) {
	out, _ := write(t, Options{},
		Section{Command: "box log", Log: "box", Run: text("2026-10-30T12:00:03Z third", "not stamped")},
		Section{Command: "k0s log", Log: "k0s", Run: text(`time="2026-10-30 12:00:01" level=info msg=first`)},
		Section{Command: "pod log", Log: "pods", Run: text("2026-10-30T08:00:02-04:00 second")},
	)
	for _, want := range []string{"2026-10-30T12:00:03.000Z third\n", "not stamped\n", "2026-10-30T12:00:02.000Z second\n"} {
		if !strings.Contains(out, want) {
			t.Fatalf("%q isn't in:\n%s", want, out)
		}
	}
	_, tl, ok := strings.Cut(out, "##### 4. timeline\n")
	if !ok {
		t.Fatalf("no timeline:\n%s", out)
	}
	first := strings.Index(tl, "[k0s]")
	second := strings.Index(tl, "[pods]")
	third := strings.Index(tl, "[box]")
	if first < 0 || second < first || third < second {
		t.Fatalf("not in time order:\n%s", tl)
	}
}

func TestTheTimelineKeepsTheNewestLines(t *testing.T) {
	var lines []string
	for i := range 20 {
		lines = append(lines, fmt.Sprintf("2026-10-30T12:00:%02dZ line%02d", i, i))
	}
	out, _ := write(t, Options{TimelineLines: 3}, Section{Command: "log", Log: "box", Run: text(lines...)})
	_, tl, _ := strings.Cut(out, "timeline\n")
	if strings.Contains(tl, "line16") || !strings.Contains(tl, "line17") || !strings.Contains(tl, "line19") {
		t.Fatalf("timeline:\n%s", tl)
	}
}

// Whatever a section does, nothing unredacted gets out: this is every way
// a section's output reaches the file.
func TestEveryPathToTheFileIsRedacted(t *testing.T) {
	secret := "password=" + plantPassword
	failing := func(ctx context.Context, w io.Writer) error {
		_, _ = io.WriteString(w, secret+"\n")
		return errors.New("failed with " + secret)
	}
	noNewline := func(_ context.Context, w io.Writer) error {
		_, err := io.WriteString(w, secret)
		return err
	}
	split := func(_ context.Context, w io.Writer) error {
		_, _ = io.WriteString(w, "passw")
		_, err := io.WriteString(w, "ord="+plantPassword+"\n")
		return err
	}
	huge := func(_ context.Context, w io.Writer) error {
		_, err := io.WriteString(w, secret+strings.Repeat("x", 2*maxLine)+"\nafter\n")
		return err
	}
	key := func(_ context.Context, w io.Writer) error {
		_, err := io.WriteString(w, pemLine("BEGIN", "")+"\n"+plantPEMBody+"\n")
		return err
	}
	out, r := write(t, Options{Known: []string{plantKnown}, Form: Full},
		Section{Command: "plain", Run: text(secret)},
		Section{Command: "a log", Log: "box", Run: text("2026-10-30T12:00:00Z " + secret)},
		Section{Command: "a tail", Tail: 5, Run: text(secret)},
		Section{Command: "a tailed log", Tail: 5, Log: "box", Run: text("2026-10-30T12:00:00Z " + secret)},
		Section{Command: "a failure", Run: failing},
		Section{Command: "no newline", Run: noNewline},
		Section{Command: "split across writes", Run: split},
		Section{Command: "a long line", Run: huge},
		Section{Command: "a key", Run: key},
		Section{Command: "next section starts clean", Run: text("still here")},
		Section{Command: "a known value", Run: text("x " + plantKnown)},
		Section{Command: "a product's own", Product: true, Redact: []*regexp.Regexp{regexp.MustCompile(`acct-[0-9]+`)}, Run: text("acct-12345")},
	)
	for _, gone := range []string{plantPassword, plantPEMBody, plantKnown, "acct-12345"} {
		if strings.Contains(out, gone) {
			t.Fatalf("%q survived:\n%s", gone, out)
		}
	}
	if !strings.Contains(out, "after\n") || !strings.Contains(out, "still here\n") {
		t.Fatalf("a section's other lines went:\n%s", out)
	}
	if r.Failed != 1 {
		t.Fatalf("report %+v", r)
	}
}

func TestProductSectionsSitUnderTheProductHeading(t *testing.T) {
	out, _ := write(t, Options{Product: "Acme"},
		Section{Command: "base", Run: text("b")},
		Section{Command: "one", Product: true, Run: text("p")},
		Section{Command: "two", Product: true, Run: text("q")},
	)
	if n := strings.Count(out, "==== Product: Acme ====\n"); n != 1 {
		t.Fatalf("%d headings:\n%s", n, out)
	}
	heading := strings.Index(out, "==== Product: Acme")
	if strings.Index(out, "1. base") > heading || heading > strings.Index(out, "2. one") {
		t.Fatalf("order:\n%s", out)
	}
}

func TestAFailedSectionDoesNotStopTheBundle(t *testing.T) {
	out, r := write(t, Options{},
		Section{Command: "broken", Run: func(context.Context, io.Writer) error { return errors.New("exit status 1") }},
		Section{Command: "absent", Optional: true, Run: func(context.Context, io.Writer) error { return errors.New("exit status 1") }},
		Section{Command: "fine", Run: text("ok")},
	)
	if !strings.Contains(out, "result: failed: exit status 1\n") || !strings.Contains(out, "result: absent\n") || !strings.Contains(out, "##### 3. fine") {
		t.Fatalf("got:\n%s", out)
	}
	if r.Failed != 1 {
		t.Fatalf("report %+v", r)
	}
}

func TestASectionIsStoppedAtItsTimeout(t *testing.T) {
	hang := func(ctx context.Context, _ io.Writer) error {
		<-ctx.Done()
		return ctx.Err()
	}
	start := time.Now()
	out, r := write(t, Options{}, Section{Command: "hangs", Timeout: 20 * time.Millisecond, Run: hang}, Section{Command: "next", Run: text("ok")})
	if time.Since(start) > 5*time.Second {
		t.Fatal("the timeout didn't hold")
	}
	if !strings.Contains(out, "result: timed out after 20ms\n") || !strings.Contains(out, "##### 2. next") {
		t.Fatalf("got:\n%s", out)
	}
	if r.Failed != 1 {
		t.Fatalf("report %+v", r)
	}
}

func TestEverySectionHasATimeout(t *testing.T) {
	var got time.Duration
	write(t, Options{}, Section{Command: "x", Run: func(ctx context.Context, _ io.Writer) error {
		d, ok := ctx.Deadline()
		if !ok {
			t.Fatal("no deadline")
		}
		got = time.Until(d)
		return nil
	}})
	if got <= 0 || got > DefaultTimeout {
		t.Fatalf("deadline %s", got)
	}
}

func TestASectionIsCutAtItsSizeAndStopped(t *testing.T) {
	var stopped bool
	flood := func(ctx context.Context, w io.Writer) error {
		for i := 0; i < 1000000; i++ {
			if ctx.Err() != nil {
				stopped = true
				return ctx.Err()
			}
			if _, err := fmt.Fprintf(w, "line %d\n", i); err != nil {
				return err
			}
		}
		return nil
	}
	out, r := write(t, Options{SectionBytes: 200}, Section{Command: "flood", Run: flood}, Section{Command: "next", Run: text("ok")})
	if !stopped {
		t.Fatal("the section kept running after its limit")
	}
	if !strings.Contains(out, "result: truncated at 200 bytes\n") || !strings.Contains(out, "##### 2. next") || r.Truncated != 1 {
		t.Fatalf("%+v got:\n%s", r, out)
	}
	if r.Failed != 0 {
		t.Fatalf("truncation isn't a failure: %+v", r)
	}
}

func TestTheBundleStopsAtItsTotalSize(t *testing.T) {
	line := strings.Repeat("x", 100)
	out, r := write(t, Options{TotalBytes: 150},
		Section{Command: "one", Run: text(line, line, line)},
		Section{Command: "two", Run: text(line)},
	)
	if !strings.Contains(out, "##### 2. two\n# skipped: the bundle's size limit\n") {
		t.Fatalf("got:\n%s", out)
	}
	if r.Truncated != 2 {
		t.Fatalf("report %+v", r)
	}
}

func TestTheBundleStopsAtItsDeadline(t *testing.T) {
	var ran bool
	hang := func(ctx context.Context, _ io.Writer) error {
		<-ctx.Done()
		return ctx.Err()
	}
	out, _ := write(t, Options{Deadline: 20 * time.Millisecond},
		Section{Command: "hangs", Run: hang},
		Section{Command: "late", Run: func(context.Context, io.Writer) error { ran = true; return nil }},
	)
	if ran || !strings.Contains(out, "##### 2. late\n# skipped: the bundle's time limit\n") {
		t.Fatalf("ran %v:\n%s", ran, out)
	}
}

func TestAClosedReaderStopsTheBundle(t *testing.T) {
	want := errors.New("the reader went away")
	var ran int
	sections := []Section{
		{Command: "one", Run: func(_ context.Context, w io.Writer) error { ran++; _, err := io.WriteString(w, "x\n"); return err }},
		{Command: "two", Run: func(context.Context, io.Writer) error { ran++; return nil }},
	}
	_, err := Write(context.Background(), failWriter{want}, Options{Form: Full, Now: clockFrom(testNow)}, sections)
	if !errors.Is(err, want) || ran > 1 {
		t.Fatalf("err %v, ran %d", err, ran)
	}
}

type failWriter struct{ err error }

func (w failWriter) Write([]byte) (int, error) { return 0, w.err }

func TestTailKeepsTheLastLines(t *testing.T) {
	out, _ := write(t, Options{}, Section{Command: "x", Tail: 2, Run: text("a1", "b2", "c3", "d4")})
	if strings.Contains(out, "b2\n") || !strings.Contains(out, "c3\nd4\n") {
		t.Fatalf("got:\n%s", out)
	}
}

// fakeExec answers by the command's words, and records every call.
type fakeExec struct {
	calls  [][]string
	answer func(argv []string) (string, error)
}

func (f *fakeExec) run(_ context.Context, argv []string, w io.Writer) error {
	f.calls = append(f.calls, argv)
	if f.answer == nil {
		return nil
	}
	out, err := f.answer(argv)
	_, _ = io.WriteString(w, out)
	return err
}

func testConfig(f *fakeExec) Config {
	return Config{
		K0s: "/slot/k0s", Kubeconfig: "/k0s/admin.conf", State: "/state", RunDir: "/run/s", Manifests: "/k0s/manifests", Progress: "/state/api/upgrade-progress.json",
		Exec:   f.run,
		Status: text("status ok"),
		Audit: func(_ context.Context, w io.Writer, n int) error {
			_, err := fmt.Fprintf(w, "audit %d\n", n)
			return err
		},
	}
}

func allArgv(t *testing.T, f *fakeExec, form Form) [][]string {
	t.Helper()
	f.answer = func(argv []string) (string, error) {
		if slices.Contains(argv, "pods") && slices.Contains(argv, "--no-headers") {
			return "sneakers gateway-1 gateway,proxy 2,0 false,true\n", nil
		}
		return "", nil
	}
	write(t, Options{Form: form}, testConfig(f).Base(form)...)
	return f.calls
}

func busyboxConfig(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.Open(filepath.Join("..", "..", "build", "busybox", "busybox.config"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	on := map[string]bool{}
	sc := bufio.NewScanner(b)
	for sc.Scan() {
		if sym, ok := strings.CutSuffix(strings.TrimSpace(sc.Text()), "=y"); ok {
			on[sym] = true
		}
	}
	return on
}

// gated are the options busybox builds only with a further option, for the
// applets the fixed set runs; an applet's other options are in its base.
var gated = map[string]map[string]string{
	"df":    {"-h": "CONFIG_FEATURE_HUMAN_READABLE"},
	"ls":    {"-laR": "CONFIG_FEATURE_LS_RECURSIVE", "--full-time": "CONFIG_FEATURE_LS_TIMESTAMPS"},
	"uname": {"-a": ""},
	"tail":  {"-n": ""},
	"ps":    {"w": "CONFIG_FEATURE_PS_WIDE"},
	"ip":    {"addr": "CONFIG_FEATURE_IP_ADDRESS", "route": "CONFIG_FEATURE_IP_ROUTE"},
}

var readOnlyApplets = []string{"cat", "date", "df", "dmesg", "free", "ip", "ls", "mount", "ps", "tail", "uname", "uptime"}

// Every command of the fixed set, in both forms, is an applet the box's
// busybox was built with, with options it was built with: 6 of 35 commands
// once failed on a box for want of one.
func TestEveryFixedCommandWorksWithTheBoxBusybox(t *testing.T) {
	on := busyboxConfig(t)
	for _, form := range []Form{Short, Full} {
		for _, argv := range allArgv(t, &fakeExec{}, form) {
			if argv[0] != Busybox {
				continue
			}
			applet := argv[1]
			if !slices.Contains(readOnlyApplets, applet) {
				t.Errorf("%s isn't on the read-only list", applet)
			}
			if !on["CONFIG_"+strings.ToUpper(applet)] {
				t.Errorf("%v: %s isn't built", argv, applet)
			}
			for _, w := range argv[2:] {
				if sym := gated[applet][w]; sym != "" && !on[sym] {
					t.Errorf("%v: %s needs %s", argv, w, sym)
				}
				if strings.HasPrefix(w, "-") {
					if _, known := gated[applet][w]; !known {
						t.Errorf("%v: %s isn't checked; add it to gated", argv, w)
					}
				}
			}
		}
	}
}

// The cluster commands only read, and none of them can carry a Secret's or
// an env var's value.
func TestEveryClusterCommandOnlyReads(t *testing.T) {
	for _, form := range []Form{Short, Full} {
		calls := allArgv(t, &fakeExec{}, form)
		kube := 0
		for _, argv := range calls {
			if argv[0] != "/slot/k0s" {
				continue
			}
			kube++
			if argv[1] == "status" {
				continue
			}
			if argv[1] != "kubectl" || argv[2] != "--kubeconfig" || argv[3] != "/k0s/admin.conf" {
				t.Fatalf("%v", argv)
			}
			verb := argv[4]
			if !slices.Contains([]string{"get", "describe", "logs"}, verb) {
				t.Errorf("%v isn't a read", argv)
			}
			line := strings.Join(argv, " ")
			if strings.Contains(line, "-o yaml") || strings.Contains(line, "-o json") || strings.Contains(line, "-ojson") {
				t.Errorf("%v prints whole objects", argv)
			}
			if verb == "describe" && strings.Contains(line, "secret") {
				t.Errorf("%v describes Secrets", argv)
			}
			if slices.Contains(argv, "secrets") && len(argv) != 7 {
				t.Errorf("%v isn't the plain table, whose rows carry no values", argv)
			}
			for _, w := range argv {
				if strings.Contains(w, ".value") || strings.Contains(w, ".data") {
					t.Errorf("%v reads a value", argv)
				}
			}
		}
		if kube == 0 {
			t.Fatal("no cluster commands")
		}
	}
}

func TestSecretsAndEnvAreNamesOnly(t *testing.T) {
	f := &fakeExec{}
	var lines []string
	for _, argv := range allArgv(t, f, Full) {
		lines = append(lines, strings.Join(argv, " "))
	}
	all := strings.Join(lines, "\n")
	if !strings.Contains(all, "get secrets -A") {
		t.Fatalf("no Secret names:\n%s", all)
	}
	if !strings.Contains(all, ".spec.containers[*].env[*].name") || !strings.Contains(all, ".spec.containers[*].envFrom[*].secretRef.name") {
		t.Fatalf("no env names:\n%s", all)
	}
}

func TestTheFixedSetCoversTheList(t *testing.T) {
	sections := testConfig(&fakeExec{}).Base(Full)
	var headings []string
	for _, s := range sections {
		headings = append(headings, s.Command)
	}
	all := strings.Join(headings, "\n")
	for _, want := range []string{
		"status", "box-values", "k0s status", "kubectl get all -A -o wide", "kubectl get events -A", "kubectl describe pods -A",
		"kubectl logs", "--previous", "console.log", "console.log.1", "prepare.log", "upgrade-progress.json", "os-audit tail",
		"mount", "df -h", "ls -laR --full-time", "phase-placed", "switches", "ps w", "kubectl get secrets -A",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("%q isn't in the set:\n%s", want, all)
		}
	}
}

// The short form is the key sections with tails of about 50 lines.
func TestTheShortFormIsSmaller(t *testing.T) {
	c := testConfig(&fakeExec{})
	short, full := c.Base(Short), c.Base(Full)
	if len(short) >= len(full) || len(short) == 0 {
		t.Fatalf("short %d, full %d", len(short), len(full))
	}
	for _, s := range short {
		if strings.Contains(s.Command, "tail -n") && !strings.Contains(s.Command, "-n 50") {
			t.Fatalf("%s", s.Command)
		}
	}
}

func TestPodLogsTakeOnlyWhatNeedsLookingAtInTheShortForm(t *testing.T) {
	f := &fakeExec{answer: func(argv []string) (string, error) {
		switch {
		case slices.Contains(argv, "--no-headers"):
			return "sneakers ok-1 web 0 true\nsneakers bad-1 app,proxy 3,0 false,true\n", nil
		case argv[4] == "logs":
			return "2026-10-30T12:00:00Z line\n", nil
		}
		return "", nil
	}}
	c := testConfig(f)
	var section, previous Section
	for _, s := range c.Base(Short) {
		if strings.HasPrefix(s.Command, "kubectl logs") {
			if strings.Contains(s.Command, "--previous") {
				previous = s
			} else {
				section = s
			}
		}
	}
	out, _ := write(t, Options{Form: Short}, section, previous)
	if strings.Contains(out, "ok-1") {
		t.Fatalf("a healthy pod is in the short form:\n%s", out)
	}
	if !strings.Contains(out, "--- sneakers/bad-1/app\n") || strings.Contains(out, "--- sneakers/bad-1/proxy\n") {
		t.Fatalf("got:\n%s", out)
	}
	var prev int
	for _, argv := range f.calls {
		if slices.Contains(argv, "--previous") {
			prev++
			if !slices.Contains(argv, "app") {
				t.Fatalf("--previous on a container with no restart: %v", argv)
			}
		}
	}
	if prev != 1 {
		t.Fatalf("%d previous calls", prev)
	}
}

func TestProductSectionsRunFromTheSpec(t *testing.T) {
	f := &fakeExec{answer: func(argv []string) (string, error) {
		return strings.Join(argv, " ") + " token=" + plantToken + "\n", nil
	}}
	spec := productspec.Spec{Support: []productspec.Support{
		{Title: "Only in full", Command: "du -s /var/lib/sneakers-data/x"},
		{Title: "In both", Short: true, Kubectl: &productspec.SupportKubectl{Verb: "logs", Namespace: "acme", Selector: "a=b"}, Redact: []string{`acct-[0-9]+`}, Timeout: "9s"},
	}}
	c := testConfig(f)
	short := c.Product(spec, Short)
	if len(short) != 1 || short[0].Command != "In both" || !short[0].Product || short[0].Timeout != 9*time.Second || short[0].Log == "" || len(short[0].Redact) != 1 {
		t.Fatalf("short %+v", short)
	}
	full := c.Product(spec, Full)
	if len(full) != 2 {
		t.Fatalf("full %+v", full)
	}
	out, _ := write(t, Options{Product: "Acme", Form: Full}, full...)
	if strings.Contains(out, plantToken) {
		t.Fatalf("a product's section isn't redacted:\n%s", out)
	}
	if !slices.Equal(f.calls[0], []string{Busybox, "du", "-s", "/var/lib/sneakers-data/x"}) {
		t.Fatalf("%v", f.calls[0])
	}
	if !slices.Contains(f.calls[1], "--tail=2000") {
		t.Fatalf("%v", f.calls[1])
	}
}

// Every section of both forms has a bound, its own or the default, and
// nothing in the base names a product.
func TestTheBaseNamesNoProduct(t *testing.T) {
	c := testConfig(&fakeExec{})
	for _, form := range []Form{Short, Full} {
		for _, s := range c.Base(form) {
			if strings.Contains(strings.ToLower(s.Command), "sneakers") && !strings.Contains(s.Command, "/state") {
				t.Fatalf("%s", s.Command)
			}
		}
	}
}
