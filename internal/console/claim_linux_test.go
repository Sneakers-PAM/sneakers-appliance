// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package console

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type lines struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lines) Read([]byte) (int, error) { select {} }

func (l *lines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lines) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// What init and the services wrote before a program claims the consoles
// is shown on them, not set aside: a line still in the shared output's
// pipe at the claim belongs before the program's screen.
func TestAClaimShowsTheLinesWrittenBeforeIt(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	serial := &lines{}
	tk := newTaken(r, nil, []Console{{Name: "ttyS0", RW: serial}}, t.Logf)
	aside := &lines{}
	tk.SetAside(aside)

	// More than the mux reads at once, so the last line is still in the
	// pipe when the claim comes.
	before := strings.Repeat("services: started service=netd\n", 2000) + "services: ready service=accessd\n"
	if _, err := w.WriteString(before); err != nil {
		t.Fatal(err)
	}
	ow, err := tk.Claim()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ow.Close() }()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.HasSuffix(serial.String(), "services: ready service=accessd\n") {
		if time.Now().After(deadline) {
			t.Fatalf("the serial line didn't show the ready line written before the claim; %d bytes went aside", len(aside.String()))
		}
		time.Sleep(5 * time.Millisecond)
	}
	if a := aside.String(); a != "" {
		t.Fatalf("%d bytes written before the claim went aside", len(a))
	}
}
