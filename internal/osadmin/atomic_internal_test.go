// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestOverlappingAtomicWritesAllSucceed(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "done")
	for range 200 {
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		for range 8 {
			wg.Go(func() { errs <- writeAtomic(p, nil) })
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	left, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 1 || left[0].Name() != "done" {
		t.Fatalf("left behind: %v", left)
	}
}
