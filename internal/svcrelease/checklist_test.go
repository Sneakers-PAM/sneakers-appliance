// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package svcrelease_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/svcrelease"
)

// fakeGitHub is a repo's state as the checklist reads it: one commit per
// tag, a default branch, commits ahead of a pinned one and the drafts.
type fakeGitHub struct {
	tags    map[string]map[string]string // repo -> tag -> commit
	branch  map[string]string            // repo -> default branch
	ahead   map[string][]svcrelease.Commit
	aheadBy map[string]int
	drafts  map[string][]svcrelease.Release
}

func (f *fakeGitHub) DefaultBranch(_ context.Context, repo string) (string, error) {
	if b := f.branch[repo]; b != "" {
		return b, nil
	}
	return "main", nil
}

func (f *fakeGitHub) TagAt(_ context.Context, repo, commit string) (string, bool, error) {
	for tag, c := range f.tags[repo] {
		if c == commit {
			return tag, true, nil
		}
	}
	return "", false, nil
}

func (f *fakeGitHub) Compare(_ context.Context, repo, _, _ string) (svcrelease.CompareResult, error) {
	return svcrelease.CompareResult{AheadBy: f.aheadBy[repo], Commits: f.ahead[repo]}, nil
}

func (f *fakeGitHub) Drafts(_ context.Context, repo string) ([]svcrelease.Release, error) {
	return f.drafts[repo], nil
}

// A mixed changed/unchanged set: rc.2's real pins (the issue's own
// example). audit changed (a draft with nothing past the pin to strip);
// sshbroker changed with a note past the pin (#35) to remove; identity is
// unchanged, with a stale draft left over to delete.
func TestChecklistMixedChangedAndUnchanged(t *testing.T) {
	f := &fakeGitHub{
		tags: map[string]map[string]string{
			"Sneakers-PAM/sneakers-identity": {"v0.1.0": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		},
		drafts: map[string][]svcrelease.Release{
			"Sneakers-PAM/sneakers-audit":     {{TagName: "v0.1.1", Draft: true, Body: "- fix: a thing (#10)"}},
			"Sneakers-PAM/sneakers-sshbroker": {{TagName: "v0.1.1", Draft: true, Body: "- feat: a thing (#34)\n- fix: another (#35)"}},
			"Sneakers-PAM/sneakers-identity":  {{TagName: "v0.0.9", Draft: true}},
		},
		ahead: map[string][]svcrelease.Commit{
			"Sneakers-PAM/sneakers-audit":     {{SHA: "c1", Message: "chore: unrelated"}},
			"Sneakers-PAM/sneakers-sshbroker": {{SHA: "c2", Message: "fix: another (#35)"}},
		},
	}
	targets := []svcrelease.Target{
		{Name: "audit", Repo: "Sneakers-PAM/sneakers-audit", Commit: "deadbeef00000000000000000000000000000d"},
		{Name: "sshbroker", Repo: "Sneakers-PAM/sneakers-sshbroker", Commit: "b2b28740000000000000000000000000000000"},
		{Name: "identity", Repo: "Sneakers-PAM/sneakers-identity", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}
	items, err := svcrelease.CheckAll(context.Background(), f, targets, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("%d items", len(items))
	}
	audit, ssh, identity := items[0], items[1], items[2]

	if audit.Unchanged || audit.NoDraft || audit.Version != "v0.1.1" || len(audit.NotesToRemove) != 0 {
		t.Fatalf("audit: %+v", audit)
	}
	if ssh.Unchanged || ssh.NoDraft || ssh.Version != "v0.1.1" || len(ssh.NotesToRemove) != 1 || ssh.NotesToRemove[0] != 35 {
		t.Fatalf("sshbroker: %+v", ssh)
	}
	if !identity.Unchanged || identity.Tag != "v0.1.0" || identity.DraftToDelete != "v0.0.9" {
		t.Fatalf("identity: %+v", identity)
	}

	out := svcrelease.Render(items)
	for _, want := range []string{
		"publish the `v0.1.1` draft",
		"Notes to remove: #35",
		"unchanged since `v0.1.0`: delete the `v0.0.9` draft",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("render lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "#10") {
		t.Fatalf("a note before the pin was flagged:\n%s", out)
	}
}

// A note mentioning a PR merged before the pin stays; only ones merged
// after it (found in the commits the default branch is ahead by) come
// out, and the target names how far ahead main is.
func TestChecklistKeepsNotesFromBeforeThePin(t *testing.T) {
	f := &fakeGitHub{
		drafts: map[string][]svcrelease.Release{
			"Sneakers-PAM/sneakers-vault": {{TagName: "v0.2.0", Draft: true, Body: "- feat: a (#1)\n- fix: b (#2)\n- fix: c (#3)"}},
		},
		ahead: map[string][]svcrelease.Commit{
			"Sneakers-PAM/sneakers-vault": {
				{SHA: "c1", Message: "fix: c (#3)"},
				{SHA: "c2", Message: "chore: unrelated, no PR number"},
			},
		},
		aheadBy: map[string]int{"Sneakers-PAM/sneakers-vault": 2},
	}
	target := svcrelease.Target{Name: "vault", Repo: "Sneakers-PAM/sneakers-vault", Commit: "0123456789012345678901234567890123456789"}
	item, err := svcrelease.Check(context.Background(), f, target, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(item.NotesToRemove) != 1 || item.NotesToRemove[0] != 3 || item.MainAheadBy != 2 || !item.Prerelease {
		t.Fatalf("%+v", item)
	}
	out := svcrelease.Render([]svcrelease.Item{item})
	if !strings.Contains(out, "main is 2 commits ahead: set the target to `0123456789012345678901234567890123456789`") {
		t.Fatalf("render:\n%s", out)
	}
	if !strings.Contains(out, "Notes to remove: #3") {
		t.Fatalf("render:\n%s", out)
	}
	if !strings.Contains(out, "Prerelease: yes") {
		t.Fatalf("render:\n%s", out)
	}
}

// No draft at all: release-drafter hasn't run.
func TestChecklistNoDraft(t *testing.T) {
	f := &fakeGitHub{}
	target := svcrelease.Target{Name: "notify", Repo: "Sneakers-PAM/sneakers-notify", Commit: "0000000000000000000000000000000000000f"}
	item, err := svcrelease.Check(context.Background(), f, target, false)
	if err != nil {
		t.Fatal(err)
	}
	if !item.NoDraft {
		t.Fatalf("%+v", item)
	}
	if out := svcrelease.Render([]svcrelease.Item{item}); !strings.Contains(out, "no draft: release-drafter hasn't run, create it first") {
		t.Fatalf("render:\n%s", out)
	}
}
