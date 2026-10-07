// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package power

import (
	"slices"
	"strings"
)

// VolumeMounts reads /proc/self/mounts and returns what a shutdown
// unmounts: every mount under /var/lib (the state and backup volumes, and
// k0s's mounts on them), deepest first, and the device-mapper names behind
// them, which are then closed. The root (dm-verity) is never among them.
func VolumeMounts(text string) (targets, mappings []string) {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		src, dst := unescape(f[0]), unescape(f[1])
		if dst != "/var/lib" && !strings.HasPrefix(dst, "/var/lib/") {
			continue
		}
		targets = append(targets, dst)
		if name, ok := strings.CutPrefix(src, "/dev/mapper/"); ok && !slices.Contains(mappings, name) {
			mappings = append(mappings, name)
		}
	}
	slices.SortStableFunc(targets, func(a, b string) int { return strings.Count(b, "/") - strings.Count(a, "/") })
	slices.Sort(mappings)
	return targets, mappings
}

// unescape undoes the kernel's octal escapes (\040 for a space).
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && isOct(s[i+1]) && isOct(s[i+2]) && isOct(s[i+3]) {
			b.WriteByte((s[i+1]-'0')<<6 | (s[i+2]-'0')<<3 | (s[i+3] - '0'))
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOct(c byte) bool { return c >= '0' && c <= '7' }
