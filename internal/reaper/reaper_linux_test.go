// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package reaper_test

import (
	"context"
	"syscall"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/reaper"
)

func TestReaperCollectsItsChildren(t *testing.T) {
	r := reaper.NewReaper()
	if err := r.Run(context.Background(), []string{"/bin/true"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Run(context.Background(), []string{"/bin/false"}); err == nil {
		t.Fatal("false must fail")
	}
	p, err := r.Start([]string{"/bin/sleep", "30"})
	if err != nil {
		t.Fatal(err)
	}
	_ = p.Signal(syscall.SIGTERM)
	if err := p.Wait(); err == nil {
		t.Fatal("a signalled sleep reports its signal")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := r.Run(ctx, []string{"/bin/sleep", "30"}); err == nil {
		t.Fatal("the context must end the run")
	}
	for i := 0; i < 50; i++ {
		if err := r.Run(context.Background(), []string{"/bin/true"}); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
}
