// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/ghrelease"
)

// releasesJSON is a releases list entry for tag, finished (with every asset
// the release job uploads) or not.
func releasesJSON(tag string, draft, pre, done bool) string {
	var assets []string
	if done {
		for _, n := range ghrelease.FinishedAssets(tag, "amd64") {
			assets = append(assets, fmt.Sprintf(`{"name":%q,"state":"uploaded"}`, n))
		}
	}
	return fmt.Sprintf(`{"tag_name":%q,"draft":%v,"prerelease":%v,"assets":[%s]}`, tag, draft, pre, strings.Join(assets, ","))
}

// release-previous names the release a tag's patches come from, from the
// API's releases list; nothing for the first release on a channel.
func TestReleasePrevious(t *testing.T) {
	list := filepath.Join(t.TempDir(), "releases.json")
	writeFile(t, list, []byte("["+releasesJSON("v0.2.0-rc.2", true, true, true)+","+releasesJSON("v0.2.0-rc.1", false, true, true)+","+releasesJSON("v0.1.0", false, false, true)+"]"))
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

// An unfinished release is skipped, and the command says which and why on
// stderr; stdout is only the tag the release job reads.
func TestReleasePreviousSkipsAnUnfinishedRelease(t *testing.T) {
	list := filepath.Join(t.TempDir(), "releases.json")
	writeFile(t, list, []byte("["+releasesJSON("v0.1.0-rc.6", false, true, false)+","+releasesJSON("v0.1.0-rc.5", false, true, true)+"]"))
	var out, errOut bytes.Buffer
	r := root()
	r.SetOut(&out)
	r.SetErr(&errOut)
	r.SetArgs([]string{"release-previous", "--releases", list, "--tag", "v0.1.0-rc.7"})
	if err := r.Execute(); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "v0.1.0-rc.5" {
		t.Fatalf("stdout %q, want v0.1.0-rc.5", got)
	}
	if e := errOut.String(); !strings.Contains(e, "skipped v0.1.0-rc.6") || !strings.Contains(e, "isn't finished") || !strings.Contains(e, "sneakers-appliance-baseOS-0.1.0-rc.6-amd64.bin") {
		t.Fatalf("stderr %q", e)
	}
}
