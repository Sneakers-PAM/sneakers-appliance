// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// The lab product bundle's phases check out the way the box checks a
// bundle: each phase's stack is there, and its workloads carry their
// phase's labels.
func TestTheLabBundlesPhasesCheckOut(t *testing.T) {
	lab := filepath.Join("..", "..", "build", "lab")
	b, err := os.ReadFile(filepath.Join(lab, "product.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := productspec.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Phases) != 2 {
		t.Fatalf("phases %+v", spec.Phases)
	}
	m := fstest.MapFS{}
	stacks, err := filepath.Glob(filepath.Join(lab, "stacks", "*", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range stacks {
		body, err := os.ReadFile(f) // #nosec G304 -- the repo's own stacks
		if err != nil {
			t.Fatal(err)
		}
		m[ProductManifests+"/"+filepath.Base(filepath.Dir(f))+"/"+filepath.Base(f)] = &fstest.MapFile{Data: body}
	}
	if err := checkPhaseStacks(m, spec); err != nil {
		t.Fatal(err)
	}
	if err := checkStacks(m); err != nil {
		t.Fatal(err)
	}
}
