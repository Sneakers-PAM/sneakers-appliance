// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productspec

import "testing"

func TestAProductNamesTheChartItsResourcesRenderFrom(t *testing.T) {
	s, err := Parse([]byte("format: 2\nresources:\n  chart: postgres-ha\n"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Resources == nil || s.Resources.Chart != "postgres-ha" {
		t.Fatalf("resources = %+v", s.Resources)
	}
}

func TestABadResourcesSectionIsRefused(t *testing.T) {
	for name, y := range map[string]string{
		"no chart":       "format: 2\nresources: {}\n",
		"an upper-case":  "format: 2\nresources:\n  chart: Postgres\n",
		"a path":         "format: 2\nresources:\n  chart: ../x\n",
		"an unknown key": "format: 2\nresources:\n  chart: pg\n  other: 1\n",
	} {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}
