// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0
// Copyright The CryptOS Authors.

// Package timesync is netd's client-only SNTPv4 (RFC 4330, and RFC 5905
// section 14): a bounded sync that steps or slews the clock, periodic polls
// after that, and a clock floor the clock is never stepped behind. It never
// serves time.
//
// Ported from CryptOS-PKI internal/timesync and extended for IPv6 servers,
// four servers, and servers that come from DHCPv6 option 56.
package timesync
