// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

const certProductYAML = productYAML + `  - secret: sneakers/sneakers-db-tls
    certificate:
      common_name: db.sneakers.svc
      dns_names: [db]
`

// projected is a pod that reads its secrets through a projected volume and
// its certificate through a secret volume, as the database's does.
const projected = off + `---
apiVersion: apps/v1
kind: Deployment
metadata: {name: sneakers-mcp}
spec:
  template:
    spec:
      containers:
        - name: mcp
          image: ghcr.io/sneakers-pam/sneakers-mcp:0.1.0
      volumes:
        - name: tls
          secret: {secretName: sneakers-db-tls}
        - name: secrets
          projected:
            sources:
              - secret:
                  name: sneakers-bundled
                  items: [{key: password, path: superuser/password}]
`

func TestABoxCertificateIsASecretAWorkloadMayMount(t *testing.T) {
	if _, _, err := run(t, projected, projected, certProductYAML); err != nil {
		t.Fatal(err)
	}
}

func TestAProjectedVolumeReadsOnlyBoxSecrets(t *testing.T) {
	for name, doc := range map[string]string{
		"a Secret no box makes": strings.Replace(projected, "name: sneakers-bundled\n                  items", "name: sneakers-other\n                  items", 1),
		"a key no box makes":    strings.Replace(projected, "{key: password, path", "{key: other, path", 1),
	} {
		if _, _, err := run(t, doc, doc, certProductYAML); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
}
