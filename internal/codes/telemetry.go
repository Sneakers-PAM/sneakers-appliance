// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package codes

import apperr "github.com/Bugs5382/go-apperr"

// The product's telemetry settings codes: 391x.
const (
	TelemetryInvalid     = 3910
	TelemetryUnreachable = 3911
	TelemetryRestart     = 3912
)

var telemetryEntries = []apperr.Entry{
	{Code: TelemetryInvalid, Symbol: "TELEMETRY_INVALID", Title: "telemetry", Cause: "a telemetry setting fails validation (the error names it)"},
	{Code: TelemetryUnreachable, Symbol: "TELEMETRY_UNREACHABLE", Title: "telemetry", Cause: "the collector didn't answer a TLS handshake when the settings were saved; nothing was saved"},
	{Code: TelemetryRestart, Symbol: "TELEMETRY_RESTART", Title: "telemetry", Cause: "there's no failed restart to retry, or a workload didn't come back in time"},
}

func init() { Entries = append(Entries, telemetryEntries...) }
