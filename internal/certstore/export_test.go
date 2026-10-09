// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package certstore

import "testing"

// SetProbePort points the default :8443 check at port for one test.
func SetProbePort(t *testing.T, port string) {
	prev := probePort
	probePort = port
	t.Cleanup(func() { probePort = prev })
}

// SetOwnName sets Options.OwnName on an opened store, for a test.
func (s *Store) SetOwnName(f func() string) { s.o.OwnName = f }
