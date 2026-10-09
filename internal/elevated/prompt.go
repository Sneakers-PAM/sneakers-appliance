// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package elevated

// Prompt is the root shell's PS1: the host name, the minutes left and the
// working directory. busybox ash expands it at each prompt
// (ASH_EXPAND_PRMT, SH_MATH, EDITING_FANCY_PROMPT; os/k0s/busybox_test.go
// checks build/busybox/busybox.config builds them).
const Prompt = `[root@\h $(( (SNEAKERS_ROOT_SHELL_ENDS - $(date +%s)) / 60 )) min left] \w # `
