// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package supportbundle

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// Both streams reach the section, a shell's error text included, and a
// failure is the command's exit.
func TestRunTakesBothStreams(t *testing.T) {
	var out bytes.Buffer
	err := Run(context.Background(), []string{"/bin/sh", "-c", "echo out; echo err >&2; exit 3"}, &out)
	if err == nil || !strings.Contains(out.String(), "out") || !strings.Contains(out.String(), "err") {
		t.Fatalf("%v %q", err, out.String())
	}
}

// A command gets none of the service's environment.
func TestRunPassesNoEnvironment(t *testing.T) {
	t.Setenv("BUNDLE_TEST_SECRET", plantToken)
	var out bytes.Buffer
	if err := Run(context.Background(), []string{"/bin/sh", "-c", "echo \"[$BUNDLE_TEST_SECRET]\""}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), plantToken) {
		t.Fatalf("got %q", out.String())
	}
}

// A command that hangs goes with its section's bound, even with a child
// holding its output open.
func TestRunStopsWithTheContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	var out bytes.Buffer
	if err := Run(ctx, []string{"/bin/sh", "-c", "sleep 30 & wait"}, &out); err == nil {
		t.Fatal("no error from a killed command")
	}
	if time.Since(start) > 10*time.Second {
		t.Fatalf("took %s", time.Since(start))
	}
}
