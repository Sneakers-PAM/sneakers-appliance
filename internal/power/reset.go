// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package power

import (
	"context"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/factoryreset"
)

// FactoryReset is the Resetter over the real reset steps.
type FactoryReset struct{ Deps factoryreset.Deps }

// Begin records the reset.
func (f FactoryReset) Begin(r factoryreset.Record) (factoryreset.Record, error) {
	return factoryreset.Begin(f.Deps, r)
}

// Run carries it out, with stop as the drain.
func (f FactoryReset) Run(ctx context.Context, stop func(context.Context) error) (factoryreset.Record, error) {
	d := f.Deps
	d.Stop = stop
	return factoryreset.Run(ctx, d)
}
