// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package elevated

import "time"

// PromptFor is the root shell's PS1 for a session that ends at ends: the
// host name, the end time and the working directory. It is plain text with
// only ash's prompt escapes (\h, \w; EDITING_FANCY_PROMPT,
// os/k0s/busybox_test.go checks build/busybox/busybox.config builds them),
// no parameter, arithmetic or command expansion, so nothing in it is ever
// run. The minute's warning before the end comes from sneakers-elevated.
func PromptFor(ends time.Time) string {
	return `[root@\h until ` + ends.UTC().Format("15:04") + ` UTC] \w # `
}
