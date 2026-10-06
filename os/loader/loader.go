// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package loader carries systemd-boot's loader.conf for the installed disk:
// no menu, no editor, no auto-detected entries, the newest sneakers entry by
// default. Secure Boot enrolment is init's job on an installed disk, so
// systemd-boot's own enrolment is off.
package loader

import _ "embed"

// Conf is loader/loader.conf.
//
//go:embed loader.conf
var Conf []byte
