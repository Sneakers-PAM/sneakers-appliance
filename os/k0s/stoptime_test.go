// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package k0s_test

import (
	"os"
	"slices"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/power"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productup"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/services"
)

// k0s's pre-stop stops the product one phase at a time, the database last
// with its own shutdown grace (2 minutes, the chart's), so the k0s entry's
// stop-timeout leaves the quiesce its bound, and a graceful reboot's drain
// leaves k0s its pre-stop and its stop.
func TestK0sStopsInTimeForTheDatabase(t *testing.T) {
	m := fstest.MapFS{}
	ents, err := os.ReadDir("../rootfs/services.d")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile("../rootfs/services.d/" + e.Name()) // #nosec G304 -- the repo's own table
		if err != nil {
			t.Fatal(err)
		}
		m[services.Dir+"/"+e.Name()] = &fstest.MapFile{Data: b}
	}
	tbl, err := services.Load(m, services.Dir)
	if err != nil {
		t.Fatal(err)
	}
	k := tbl["k0s"]
	if !slices.Equal(k.PreStop, []string{"/usr/bin/sneakers-accessd", "quiesce"}) {
		t.Fatalf("k0s pre-stop %v", k.PreStop)
	}
	if k.StopTimeout != 5*time.Minute {
		t.Fatalf("k0s stop-timeout %v, want 5m", k.StopTimeout)
	}
	if productup.QuiesceBound < 4*time.Minute || productup.QuiesceBound >= k.StopTimeout {
		t.Fatalf("the quiesce's bound %v doesn't fit the stop-timeout %v with room for the database's 2 minute grace", productup.QuiesceBound, k.StopTimeout)
	}
	if power.DefaultDrainTimeout < k.StopTimeout+2*time.Minute {
		t.Fatalf("a drain gets %v, less than k0s's pre-stop %v and its stop", power.DefaultDrainTimeout, k.StopTimeout)
	}
}
