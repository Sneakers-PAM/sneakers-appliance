// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package svcrelease_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/svcrelease"
)

// API reads the shapes the real GitHub REST API answers with: the repo's
// default branch, its tags (matched by the commit they resolve to), a
// compare's ahead_by and commits, and the releases list filtered to
// drafts.
func TestAPIReadsGitHubsShapes(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok-1" {
			t.Errorf("no bearer token: %q", got)
		}
		switch r.URL.Path {
		case "/repos/o/r":
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		case "/repos/o/r/tags":
			_, _ = w.Write([]byte(`[{"name":"v0.1.1","commit":{"sha":"aaaa"}},{"name":"v0.1.0","commit":{"sha":"bbbb"}}]`))
		case "/repos/o/r/compare/bbbb...main":
			_, _ = w.Write([]byte(`{"ahead_by":2,"commits":[{"sha":"c1","commit":{"message":"feat: a (#1)"}},{"sha":"c2","commit":{"message":"fix: b (#2)"}}]}`))
		case "/repos/o/r/releases":
			_, _ = w.Write([]byte(`[{"tag_name":"v0.2.0","draft":true,"body":"notes"},{"tag_name":"v0.1.1","draft":false,"body":"published"}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	api := svcrelease.API{BaseURL: ts.URL, Token: "tok-1"}
	ctx := context.Background()

	if b, err := api.DefaultBranch(ctx, "o/r"); err != nil || b != "main" {
		t.Fatalf("%v %v", b, err)
	}
	if tag, ok, err := api.TagAt(ctx, "o/r", "aaaa"); err != nil || !ok || tag != "v0.1.1" {
		t.Fatalf("%v %v %v", tag, ok, err)
	}
	if _, ok, err := api.TagAt(ctx, "o/r", "cccc"); err != nil || ok {
		t.Fatalf("a commit with no tag: %v %v", ok, err)
	}
	cmp, err := api.Compare(ctx, "o/r", "bbbb", "main")
	if err != nil || cmp.AheadBy != 2 || len(cmp.Commits) != 2 || cmp.Commits[1].Message != "fix: b (#2)" {
		t.Fatalf("%+v %v", cmp, err)
	}
	drafts, err := api.Drafts(ctx, "o/r")
	if err != nil || len(drafts) != 1 || drafts[0].TagName != "v0.2.0" || !drafts[0].Draft {
		t.Fatalf("%+v %v", drafts, err)
	}
}
