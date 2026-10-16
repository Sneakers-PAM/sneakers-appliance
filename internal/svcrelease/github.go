// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package svcrelease

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// GitHub is the read-only GitHub access the checklist needs for one
// repository: its default branch, whether a tag already names a commit,
// how far a commit is behind the default branch and the commits between,
// and its draft releases. A fake in tests stands in for the real one.
type GitHub interface {
	DefaultBranch(ctx context.Context, repo string) (string, error)
	TagAt(ctx context.Context, repo, commit string) (tag string, ok bool, err error)
	Compare(ctx context.Context, repo, base, head string) (CompareResult, error)
	Drafts(ctx context.Context, repo string) ([]Release, error)
}

// CompareResult is GitHub's compare of base...head: aheadBy commits, head
// is ahead of base by, each one's SHA and commit message (oldest first,
// as the API returns them).
type CompareResult struct {
	AheadBy int
	Commits []Commit
}

// Commit is one commit's SHA and message.
type Commit struct{ SHA, Message string }

// Release is one release or draft, as far as the checklist reads it.
type Release struct {
	TagName string
	Draft   bool
	Body    string
}

// maxBody caps one API answer this tool reads.
const maxBody = 4 << 20

// API is GitHub read against the REST API (unauthenticated, or with a
// token for a private repo or the higher rate limit). BaseURL is
// api.github.com's URL in production; a test points it at a fake server.
type API struct {
	HTTP    *http.Client
	BaseURL string
	// Token is sent as a bearer token when set.
	Token string
}

func (a API) client() *http.Client {
	if a.HTTP != nil {
		return a.HTTP
	}
	return http.DefaultClient
}

func (a API) base() string {
	if a.BaseURL != "" {
		return a.BaseURL
	}
	return "https://api.github.com"
}

func (a API) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.base()+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "sneakers-appliance-svcrelease")
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
	resp, err := a.client().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return err
	}
	if len(b) > maxBody {
		return fmt.Errorf("GET %s: answer over %d bytes", path, maxBody)
	}
	return json.Unmarshal(b, out)
}

func (a API) DefaultBranch(ctx context.Context, repo string) (string, error) {
	var out struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := a.get(ctx, "/repos/"+repo, &out); err != nil {
		return "", err
	}
	if out.DefaultBranch == "" {
		return "", fmt.Errorf("%s: no default branch", repo)
	}
	return out.DefaultBranch, nil
}

// TagAt is whether repo has a tag (the newest, if more than one) at
// commit, from its most recent 100 tags: enough for a repo whose release
// cadence keeps to the current and previous handful.
func (a API) TagAt(ctx context.Context, repo, commit string) (string, bool, error) {
	var tags []struct {
		Name   string `json:"name"`
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	if err := a.get(ctx, "/repos/"+repo+"/tags?per_page=100", &tags); err != nil {
		return "", false, err
	}
	for _, t := range tags {
		if t.Commit.SHA == commit {
			return t.Name, true, nil
		}
	}
	return "", false, nil
}

func (a API) Compare(ctx context.Context, repo, base, head string) (CompareResult, error) {
	var out struct {
		AheadBy int `json:"ahead_by"`
		Commits []struct {
			SHA    string `json:"sha"`
			Commit struct {
				Message string `json:"message"`
			} `json:"commit"`
		} `json:"commits"`
	}
	if err := a.get(ctx, "/repos/"+repo+"/compare/"+base+"..."+head, &out); err != nil {
		return CompareResult{}, err
	}
	res := CompareResult{AheadBy: out.AheadBy}
	for _, c := range out.Commits {
		res.Commits = append(res.Commits, Commit{SHA: c.SHA, Message: c.Commit.Message})
	}
	return res, nil
}

// Drafts is every draft release of repo, from its most recent 100
// releases.
func (a API) Drafts(ctx context.Context, repo string) ([]Release, error) {
	var rels []struct {
		TagName string `json:"tag_name"`
		Draft   bool   `json:"draft"`
		Body    string `json:"body"`
	}
	if err := a.get(ctx, "/repos/"+repo+"/releases?per_page=100", &rels); err != nil {
		return nil, err
	}
	var out []Release
	for _, r := range rels {
		if r.Draft {
			out = append(out, Release{TagName: r.TagName, Draft: true, Body: r.Body})
		}
	}
	return out, nil
}
