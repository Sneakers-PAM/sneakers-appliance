// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package certstore

import (
	"context"
	"testing"
	"time"
)

// SetProbePort points the default :8443 check at port for one test.
func SetProbePort(t *testing.T, port string) {
	prev := probePort
	probePort = port
	t.Cleanup(func() { probePort = prev })
}

// SetOwnName sets Options.OwnName on an opened store, for a test.
func (s *Store) SetOwnName(f func() string) { s.o.OwnName = f }

// SetNow sets Options.Now on an opened store, for a test.
func (s *Store) SetNow(now func() time.Time) { s.o.Now = now }

// SetFallback sets Options.Fallback on an opened store, for a test.
func (s *Store) SetFallback(f func() error) { s.o.Fallback = f }

// SetProduct sets Options.Product and Options.ProductProbe on an opened
// store, for a test.
func (s *Store) SetProduct(e ProductEdge, probe func(ctx context.Context, fingerprint string) error) {
	s.o.Product, s.o.ProductProbe = e, probe
}
