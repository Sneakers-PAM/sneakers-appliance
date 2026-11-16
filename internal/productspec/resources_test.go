// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productspec

import (
	"strings"
	"testing"
)

func TestAProductNamesTheChartItsResourcesRenderFrom(t *testing.T) {
	s, err := Parse([]byte(fullResources))
	if err != nil {
		t.Fatal(err)
	}
	r := s.Resources
	if r == nil || r.Chart != "postgres-ha" || r.Phase != "data" || r.Release != "sneakers-pgha" ||
		r.Namespace != "sneakers" || r.Data != "/var/lib/sneakers-data" || r.WaitJob != "migrate" {
		t.Fatalf("resources = %+v", r)
	}
	if r.Values["fullnameOverride"] != "sneakers-pgha" {
		t.Fatalf("values = %+v", r.Values)
	}
}

const fullResources = `format: 2
phases:
  - name: data
    label: Starting the database
    stack: sneakers-data
    workloads: [sneakers-pgha]
resources:
  chart: postgres-ha
  phase: data
  release: sneakers-pgha
  namespace: sneakers
  data: /var/lib/sneakers-data
  wait_job: migrate
  values:
    fullnameOverride: sneakers-pgha
    postgresql:
      parameters:
        max_connections: 100
`

func withResources(old, new string) string { return strings.Replace(fullResources, old, new, 1) }

func TestABadResourcesSectionIsRefused(t *testing.T) {
	for name, y := range map[string]string{
		"no chart":          "format: 2\nresources: {}\n",
		"an upper-case":     withResources("chart: postgres-ha", "chart: Postgres"),
		"a path":            withResources("chart: postgres-ha", "chart: ../x"),
		"an unknown key":    withResources("wait_job: migrate", "wait_job: migrate\n  other: 1"),
		"no phase":          withResources("  phase: data\n", ""),
		"a phase not there": withResources("phase: data", "phase: later"),
		"no release":        withResources("  release: sneakers-pgha\n", ""),
		"a bad release":     withResources("release: sneakers-pgha", "release: Sneakers_PGHA"),
		"no namespace":      withResources("  namespace: sneakers\n", ""),
		"a bad namespace":   withResources("namespace: sneakers", "namespace: a/b"),
		"no data":           withResources("  data: /var/lib/sneakers-data\n", ""),
		"a relative data":   withResources("data: /var/lib/sneakers-data", "data: var/lib"),
		"a bad wait job":    withResources("wait_job: migrate", "wait_job: Mig rate"),
	} {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// A base before rc.8 refuses a product.yaml with a resources section, so a
// bundle that has one is never sealed for it.
func TestAResourcesSectionNeedsTheBaseThatRendersIt(t *testing.T) {
	s, err := Parse([]byte(fullResources))
	if err != nil {
		t.Fatal(err)
	}
	floor, why := s.BaseFloor()
	if floor != ResourcesMinBase || !strings.Contains(why, "resources") {
		t.Fatalf("the floor: %q %q", floor, why)
	}
}
