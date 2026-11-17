// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package updatepkg

import "testing"

func TestMergeKeepsTheReceiversEntryForAFileBothList(t *testing.T) {
	newer := Index{Format: 2, Products: []IndexEntry{{Version: "0.2.0", File: "p-0.2.0.bin", Size: 2}, {Version: "0.1.1", File: "p-0.1.1.bin", Size: 11}}}
	older := Index{Format: 2, Products: []IndexEntry{{Version: "0.1.1", File: "p-0.1.1.bin", Size: 99}, {Version: "0.1.0", File: "p-0.1.0.bin", Size: 10}},
		BaseOS: []IndexEntry{{Version: "0.1.0", Kind: "patch", File: "b-patch.bin"}}}
	got := newer.Merge(older)
	var files []string
	for _, e := range got.Products {
		files = append(files, e.File)
	}
	if len(got.Products) != 3 || files[0] != "p-0.2.0.bin" || files[1] != "p-0.1.1.bin" || files[2] != "p-0.1.0.bin" {
		t.Fatalf("products %v", files)
	}
	if got.Products[1].Size != 11 {
		t.Fatalf("the older release's entry replaced the newer's: %+v", got.Products[1])
	}
	if len(got.BaseOS) != 1 || got.Format != 2 {
		t.Fatalf("base os %v, format %d", got.BaseOS, got.Format)
	}
	if len(newer.Products) != 2 {
		t.Fatal("the receiver changed")
	}
}
