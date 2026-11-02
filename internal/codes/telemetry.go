// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package codes

import apperr "github.com/Bugs5382/go-apperr"

// The product's telemetry settings codes: 391x.
const (
	TelemetryInvalid = 3910
)

var telemetryEntries = []apperr.Entry{
	{Code: TelemetryInvalid, Symbol: "TELEMETRY_INVALID", Title: "telemetry", Cause: "a telemetry setting fails validation (the error names it)"},
}

func init() { Entries = append(Entries, telemetryEntries...) }
