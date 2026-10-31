// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

const bundleText = "##### support-bundle\n\n==== Product: Acme ====\n\n##### 1. status\n# started: 2026-10-30T16:00:00Z\nall good\nlevel=error something broke\nwarning: disk is filling\n# ended: 2026-10-30T16:00:01Z result: failed: exit status 1\n"

type bundleBackend struct{ got []Request }

func (b *bundleBackend) Call(_ context.Context, r Request) (Result, error) {
	b.got = append(b.got, r)
	return Result{Stream: strings.NewReader(bundleText)}, nil
}

func runBundle(t *testing.T, line string, terminal bool, o Origin) (string, *bundleBackend, error) {
	t.Helper()
	be := &bundleBackend{}
	var out, errs bytes.Buffer
	e := &Env{Origin: o, Backend: be, In: strings.NewReader(""), Out: &out, Err: &errs, Terminal: terminal}
	err := Run(context.Background(), e, line)
	return out.String(), be, err
}

func TestSupportBundleAsksForTheForm(t *testing.T) {
	_, be, err := runBundle(t, "support-bundle", false, OriginSSH)
	if err != nil || len(be.got) != 1 || be.got[0].Action != "support.bundle" || len(be.got[0].Args) != 0 {
		t.Fatalf("%v %+v", err, be.got)
	}
	_, be, err = runBundle(t, "support-bundle full", false, OriginSSH)
	if err != nil || len(be.got) != 1 || be.got[0].Args[0] != "full" {
		t.Fatalf("%v %+v", err, be.got)
	}
}

func TestSupportBundleRefusesAnythingElse(t *testing.T) {
	_, be, err := runBundle(t, "support-bundle everything", false, OriginSSH)
	if !codes.Is(err, codes.ShellParse) || len(be.got) != 0 {
		t.Fatalf("%v %+v", err, be.got)
	}
}

func TestSupportBundleIsNotOnTheConsole(t *testing.T) {
	if _, be, err := runBundle(t, "support-bundle", true, OriginConsole); err == nil || len(be.got) != 0 {
		t.Fatalf("%v %+v", err, be.got)
	}
}

// Anything that isn't a terminal gets the plain text, with no escapes.
func TestSupportBundleIsPlainOffATerminal(t *testing.T) {
	out, _, err := runBundle(t, "support-bundle", false, OriginSSH)
	if err != nil || out != bundleText {
		t.Fatalf("%v %q", err, out)
	}
}

func TestSupportBundleNoColorFlag(t *testing.T) {
	out, _, err := runBundle(t, "support-bundle --no-color", true, OriginSSH)
	if err != nil || out != bundleText {
		t.Fatalf("%v %q", err, out)
	}
	out, _, err = runBundle(t, "support-bundle full --no-color", true, OriginSSH)
	if err != nil || out != bundleText {
		t.Fatalf("%v %q", err, out)
	}
}

// On a terminal the headings, errors and warnings stand out; the text is
// otherwise the same, so a selection copies the same words.
func TestSupportBundleColoursATerminal(t *testing.T) {
	out, _, err := runBundle(t, "support-bundle", true, OriginSSH)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		colorHeading + "##### 1. status" + colorReset + "\n",
		colorHeading + "==== Product: Acme ====" + colorReset + "\n",
		colorError + "level=error something broke" + colorReset + "\n",
		colorWarn + "warning: disk is filling" + colorReset + "\n",
		colorError + "# ended: 2026-10-30T16:00:01Z result: failed: exit status 1" + colorReset + "\n",
		"all good\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("%q isn't in %q", want, out)
		}
	}
	plain := out
	for _, c := range []string{colorHeading, colorError, colorWarn, colorReset} {
		plain = strings.ReplaceAll(plain, c, "")
	}
	if plain != bundleText {
		t.Fatalf("the text changed: %q", plain)
	}
}

func TestColourPassesAReadError(t *testing.T) {
	r := colourBundle(io.MultiReader(strings.NewReader("line"), errReader{}))
	b, err := io.ReadAll(r)
	if err == nil || !strings.Contains(string(b), "line") {
		t.Fatalf("%v %q", err, b)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
