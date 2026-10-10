// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"testing"
)

// release-previous names the release a tag's patches come from, from the
// API's releases list; nothing for the first release on a channel.
func TestReleasePrevious(t *testing.T) {
	list := filepath.Join(t.TempDir(), "releases.json")
	writeFile(t, list, []byte(`[{"tag_name":"v0.2.0-rc.2","draft":true,"prerelease":true},{"tag_name":"v0.2.0-rc.1","prerelease":true},{"tag_name":"v0.1.0"}]`))
	for tag, want := range map[string]string{"v0.2.0-rc.2": "v0.2.0-rc.1", "v0.2.0": "v0.1.0", "v0.1.0": ""} {
		got, err := runCmd(t, "release-previous", "--releases", list, "--tag", tag)
		if err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", tag, got, err, want)
		}
	}
	if _, err := runCmd(t, "release-previous", "--releases", list, "--tag", "0.2.0"); err == nil {
		t.Error("a tag without the v was taken")
	}
}
