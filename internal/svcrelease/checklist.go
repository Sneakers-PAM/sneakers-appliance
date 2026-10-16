// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package svcrelease

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Item is one target's checklist entry.
type Item struct {
	Target Target

	// Unchanged is true when the pinned commit already carries a tag
	// (Tag): nothing to publish. DraftToDelete, if not empty, is a draft
	// release-drafter left for that version, now stale.
	Unchanged     bool
	Tag           string
	DraftToDelete string

	// NoDraft is true when the commit changed but release-drafter hasn't
	// made a draft for it yet.
	NoDraft bool

	// Version, Target40, NotesToRemove and LineToAdd are set when the
	// commit changed and a draft is there to publish. Target40 is the
	// full pinned SHA; MainAheadBy is how many commits the repo's default
	// branch is ahead of it (0 when the pin already is the branch's HEAD).
	Version       string
	Target40      string
	MainAheadBy   int
	NotesToRemove []int
	LineToAdd     string
	Prerelease    bool

	// OtherDrafts are stale drafts on this repo beyond the one above (a
	// leftover for another tag): always listed as "delete".
	OtherDrafts []string
}

var (
	prInCommitMessage = regexp.MustCompile(`\(#(\d+)\)`)
	prInNotes         = regexp.MustCompile(`#(\d+)`)
)

// Check is t's checklist item against gh. prerelease is whether the
// appliance release being checked is itself one, which Item.Prerelease
// carries for a changed target.
func Check(ctx context.Context, gh GitHub, t Target, prerelease bool) (Item, error) {
	tag, ok, err := gh.TagAt(ctx, t.Repo, t.Commit)
	if err != nil {
		return Item{}, fmt.Errorf("%s (%s): %w", t.Name, t.Repo, err)
	}
	drafts, err := gh.Drafts(ctx, t.Repo)
	if err != nil {
		return Item{}, fmt.Errorf("%s (%s): %w", t.Name, t.Repo, err)
	}

	if ok {
		item := Item{Target: t, Unchanged: true, Tag: tag}
		if len(drafts) > 0 {
			item.DraftToDelete = drafts[0].TagName
			for _, d := range drafts[1:] {
				item.OtherDrafts = append(item.OtherDrafts, d.TagName)
			}
		}
		return item, nil
	}
	if len(drafts) == 0 {
		return Item{Target: t, NoDraft: true}, nil
	}
	draft := drafts[0]
	var other []string
	for _, d := range drafts[1:] {
		other = append(other, d.TagName)
	}

	branch, err := gh.DefaultBranch(ctx, t.Repo)
	if err != nil {
		return Item{}, fmt.Errorf("%s (%s): %w", t.Name, t.Repo, err)
	}
	cmp, err := gh.Compare(ctx, t.Repo, t.Commit, branch)
	if err != nil {
		return Item{}, fmt.Errorf("%s (%s): %w", t.Name, t.Repo, err)
	}

	afterPin := map[int]bool{}
	for _, c := range cmp.Commits {
		if m := prInCommitMessage.FindStringSubmatch(c.Message); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				afterPin[n] = true
			}
		}
	}
	var remove []int
	seen := map[int]bool{}
	for _, m := range prInNotes.FindAllStringSubmatch(draft.Body, -1) {
		n, err := strconv.Atoi(m[1])
		if err != nil || seen[n] || !afterPin[n] {
			continue
		}
		seen[n] = true
		remove = append(remove, n)
	}
	sort.Ints(remove)

	return Item{
		Target: t, Version: draft.TagName, Target40: t.Commit, MainAheadBy: cmp.AheadBy,
		NotesToRemove: remove, LineToAdd: "Image built from `" + t.Commit + "`",
		Prerelease: prerelease, OtherDrafts: other,
	}, nil
}

// CheckAll is Check for every target, in order; the first error stops it
// (a repo the token can't read, or a bad response), naming which target.
func CheckAll(ctx context.Context, gh GitHub, targets []Target, prerelease bool) ([]Item, error) {
	out := make([]Item, 0, len(targets))
	for _, t := range targets {
		item, err := Check(ctx, gh, t, prerelease)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// Render is items as the Markdown checklist, in the order to do it, under
// its own heading: the release's job summary and notes both get it as is.
func Render(items []Item) string {
	var b strings.Builder
	b.WriteString("## Service repo releases\n\n")
	for _, it := range items {
		page := "https://github.com/" + it.Target.Repo + "/releases"
		switch {
		case it.Unchanged:
			fmt.Fprintf(&b, "- **%s** ([%s](%s)): unchanged since `%s`", it.Target.Name, it.Target.Repo, page, it.Tag)
			if it.DraftToDelete != "" {
				fmt.Fprintf(&b, ": delete the `%s` draft", it.DraftToDelete)
			}
			b.WriteString("\n")
		case it.NoDraft:
			fmt.Fprintf(&b, "- **%s** ([%s](%s)): no draft: release-drafter hasn't run, create it first\n", it.Target.Name, it.Target.Repo, page)
		default:
			fmt.Fprintf(&b, "- **%s** ([%s](%s)): publish the `%s` draft\n", it.Target.Name, it.Target.Repo, page, it.Version)
			fmt.Fprintf(&b, "  - Target: `%s`", it.Target40)
			if it.MainAheadBy > 0 {
				fmt.Fprintf(&b, " (main is %s ahead: set the target to `%s`)", plural(it.MainAheadBy, "commit"), it.Target40)
			}
			b.WriteString("\n")
			if len(it.NotesToRemove) > 0 {
				b.WriteString("  - Notes to remove:")
				for i, n := range it.NotesToRemove {
					if i > 0 {
						b.WriteString(",")
					}
					fmt.Fprintf(&b, " #%d", n)
				}
				b.WriteString("\n")
			}
			fmt.Fprintf(&b, "  - Line to add: \"%s\"\n", it.LineToAdd)
			if it.Prerelease {
				b.WriteString("  - Prerelease: yes\n")
			}
		}
		for _, d := range it.OtherDrafts {
			fmt.Fprintf(&b, "  - delete the stale `%s` draft\n", d)
		}
	}
	return b.String()
}
