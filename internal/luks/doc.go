// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package luks opens and (on first boot) formats the encrypted state
// partition. The LUKS2 master key is sealed to TPM PCRs {7, 11} using
// the systemd-tpm2 on-disk token schema for compatibility with the
// standard cryptsetup tooling. We invoke a static cryptsetup binary
// embedded in the rootfs rather than reimplementing LUKS2 metadata
// parsing.
package luks
