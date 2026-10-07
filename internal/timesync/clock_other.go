// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package timesync

import (
	"errors"
	"time"
)

// SystemClock returns a clock that reads the host time but refuses to adjust
// it: only a Linux appliance disciplines its clock.
func SystemClock() Clock { return otherClock{} }

type otherClock struct{}

var errUnsupported = errors.New("timesync: adjusting the clock is supported only on Linux")

func (otherClock) Now() time.Time                 { return time.Now() }
func (otherClock) Step(time.Duration) error       { return errUnsupported }
func (otherClock) Slew(time.Duration) error       { return errUnsupported }
func (otherClock) MarkSynced(time.Duration) error { return errUnsupported }
