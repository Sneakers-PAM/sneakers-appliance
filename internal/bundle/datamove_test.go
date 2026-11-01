// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bundle_test

import (
	"testing"
	"testing/fstest"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sigbundle"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
)

const moveSpec = `format: 2
phases:
  - {name: data, label: Data, stack: st-data, workloads: [old-db, new-db]}
  - {name: app, label: App, stack: st-app, workloads: [api]}
data_move:
  label: Moving
  after: data
  databases: [one]
  source: {namespace: app, name: old-db, host: 127.0.0.1, user: postgres}
  target: {namespace: app, name: new-db, host: 127.0.0.1, user: postgres}
  checks:
    - {name: chain, database: one, file: datamove/chain.sql}
`

func TestAProductCarriesItsDataMoveChecks(t *testing.T) {
	k := fixtures.LabKeys(t)
	pub, _ := sigbundle.ParsePublicKey(k.Cosign.PublicPEM)
	spec := func(m fstest.MapFS) {
		m[bundle.ProductSpec] = &fstest.MapFile{Data: []byte(moveSpec)}
		for _, st := range []string{"st-data", "st-app"} {
			m[bundle.ProductManifests+"/"+st+"/"+st+".yaml"] = &fstest.MapFile{Data: []byte("kind: ConfigMap\n")}
		}
	}
	tree, _ := fixtures.ProductTree(t, k, "amd64", func(m fstest.MapFS) {
		spec(m)
	})
	if _, err := bundle.CheckProduct(tree, "amd64", pub); !codes.Is(err, codes.KitBundleMismatch) {
		t.Fatalf("a bundle without its check: want KIT_BUNDLE_MISMATCH, got %v", err)
	}
	tree, _ = fixtures.ProductTree(t, k, "amd64", func(m fstest.MapFS) {
		spec(m)
		m[bundle.ProductDataMove+"/chain.sql"] = &fstest.MapFile{Data: []byte("SELECT 'ok';\n")}
	})
	if _, err := bundle.CheckProduct(tree, "amd64", pub); err != nil {
		t.Fatal(err)
	}
}
