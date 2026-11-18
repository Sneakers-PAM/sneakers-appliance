// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package updatepkg

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAnIndexWithAWithdrawnListRoundTrips(t *testing.T) {
	in := `{"format":2,"products":[],"withdrawn":[{"kind":"product","version":"0.1.0-rc.9","reason":"an update from rc.6 fails; use rc.10","use":"0.1.0-rc.10"}]}`
	var idx Index
	if err := json.Unmarshal([]byte(in), &idx); err != nil {
		t.Fatal(err)
	}
	w, ok := idx.WithdrawnFor("product", "0.1.0-rc.9")
	if !ok || w.Reason != "an update from rc.6 fails; use rc.10" || w.Use != "0.1.0-rc.10" {
		t.Fatalf("withdrawn %+v %v", w, ok)
	}
	if _, ok := idx.WithdrawnFor("product", "0.1.0-rc.10"); ok {
		t.Fatal("a version that isn't listed is withdrawn")
	}
	if _, ok := idx.WithdrawnFor("baseOS", "0.1.0-rc.9"); ok {
		t.Fatal("a marker for a product withdrew a Base OS")
	}
	// An index from before the list has none, and writes none.
	var old Index
	if err := json.Unmarshal([]byte(`{"format":2,"products":[]}`), &old); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(old)
	if len(old.Withdrawn) != 0 || strings.Contains(string(b), "withdrawn") {
		t.Fatalf("an index without the list: %+v %s", old.Withdrawn, b)
	}
}

func TestMergeKeepsEveryIndexsWithdrawnOnce(t *testing.T) {
	newer := Index{Withdrawn: []Withdrawn{{Kind: "product", Version: "0.1.0-rc.9", Reason: "new reason", Use: "0.1.0-rc.10"}}}
	older := Index{Withdrawn: []Withdrawn{{Kind: "product", Version: "0.1.0-rc.9", Reason: "old reason"}, {Kind: "product", Version: "0.1.0-rc.7", Reason: "r7"}}}
	got := newer.Merge(older)
	if len(got.Withdrawn) != 2 {
		t.Fatalf("withdrawn %+v", got.Withdrawn)
	}
	if w, _ := got.WithdrawnFor("product", "0.1.0-rc.9"); w.Reason != "new reason" {
		t.Fatalf("the older index's marker replaced the newer's: %+v", w)
	}
}

func TestAWithdrawnListIsChecked(t *testing.T) {
	for name, w := range map[string]Withdrawn{
		"a kind that isn't one":  {Kind: "firmware", Version: "0.1.0", Reason: "r"},
		"no version":             {Kind: "product", Reason: "r"},
		"a version that isn't":   {Kind: "product", Version: "rc9", Reason: "r"},
		"no reason":              {Kind: "product", Version: "0.1.0"},
		"a use that isn't":       {Kind: "product", Version: "0.1.0", Reason: "r", Use: "latest"},
		"a release used instead": {Kind: "product", Version: "0.1.0", Reason: "r", Use: "0.1.0"},
	} {
		if err := (Index{Withdrawn: []Withdrawn{w}}).ValidateWithdrawn(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	ok := Index{Withdrawn: []Withdrawn{{Kind: "product", Version: "0.1.0-rc.9", Reason: "r", Use: "0.1.0-rc.10"}, {Kind: "baseOS", Version: "0.1.0-rc.9", Reason: "r"}}}
	if err := ok.ValidateWithdrawn(); err != nil {
		t.Fatal(err)
	}
}
