// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productsetup

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// StatePath is the product gateway's setup state, through the API
// server's service proxy: {"needsSetup": true} until its first admin
// exists.
const StatePath = "/api/v1/namespaces/sneakers/services/sneakers-gateway:http/proxy/setup/state"

// probeTimeout bounds one ask.
const probeTimeout = 10 * time.Second

// KubectlProbe asks the product whether it still needs its first admin,
// with the installed bundle's k0s acting as kubectl on the admin
// kubeconfig. Any failure (k0s down, the gateway not ready) is an error:
// the caller keeps the token.
func KubectlProbe(k0s, kubeconfig string) func(context.Context) (bool, error) {
	return func(ctx context.Context) (bool, error) {
		ctx, cancel := context.WithTimeout(ctx, probeTimeout)
		defer cancel()
		var out, errb bytes.Buffer
		cmd := exec.CommandContext(ctx, k0s, "kubectl", "--kubeconfig", kubeconfig, "get", "--raw", StatePath) // #nosec G204 -- the installed bundle's k0s
		cmd.Stdout, cmd.Stderr = &out, &errb
		if err := cmd.Run(); err != nil {
			return false, fmt.Errorf("product setup state: %w: %s", err, strings.TrimSpace(out.String()+" "+errb.String()))
		}
		var st struct {
			NeedsSetup *bool `json:"needsSetup"`
		}
		if err := json.Unmarshal(out.Bytes(), &st); err != nil || st.NeedsSetup == nil {
			return false, fmt.Errorf("product setup state: the gateway's answer has no needsSetup")
		}
		return *st.NeedsSetup, nil
	}
}
