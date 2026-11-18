// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/mod/semver"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/sigbundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

// Feed channels: rc follows the release candidates and the stable releases,
// stable only the stable ones.
const (
	feedRC     = "rc"
	feedStable = "stable"
)

// feedIndexCmd builds the update feed's index from the published releases.
// It never signs: the feed is signed in the website repository's
// feed-signing environment, over the exact bytes this writes.
func feedIndexCmd() *cobra.Command {
	var channel, key, releases, withdrawn, previous, generatedAt, docs, out string
	var sequence int64
	cmd := &cobra.Command{
		Use:   "feed-index",
		Short: "Build the unsigned update feed index from the published releases and the withdrawn list",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if channel != feedRC && channel != feedStable {
				return fmt.Errorf("--channel %q is not rc or stable", channel)
			}
			seq, err := feedSequence(previous, sequence, cmd.Flags().Changed("sequence"), channel)
			if err != nil {
				return err
			}
			at := generatedAt
			if at == "" {
				at = time.Now().UTC().Format(time.RFC3339)
			} else if _, err := time.Parse(time.RFC3339, at); err != nil {
				return fmt.Errorf("--generated-at %q is not RFC 3339: %w", at, err)
			}
			pemBytes, err := os.ReadFile(key) // #nosec G304 -- a public key named by the operator
			if err != nil {
				return err
			}
			pub, err := sigbundle.ParsePublicKey(pemBytes)
			if err != nil {
				return fmt.Errorf("--release-key %s: %w", key, err)
			}
			idx, tags, err := buildFeed(releases, channel, docs, pub)
			if err != nil {
				return err
			}
			list, err := readWithdrawn(withdrawn)
			if err != nil {
				return err
			}
			idx.Withdrawn = list
			idx.Feed = &updatepkg.FeedMeta{Channel: channel, Sequence: seq, GeneratedAt: at}
			if err := idx.ValidateWithdrawn(); err != nil {
				return err
			}
			b, err := json.MarshalIndent(idx, "", "  ")
			if err != nil {
				return err
			}
			if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil { // #nosec G306 G703 -- a public index
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s: %s feed sequence %d from %s\n", out, channel, seq, strings.Join(tags, ", "))
			return err
		},
	}
	f := cmd.Flags()
	f.StringVar(&channel, "channel", "", "the feed's channel: rc or stable")
	f.StringVar(&key, "release-key", "", "the release public key the releases' indexes and SHA256SUMS are signed with (cosign.pub)")
	f.StringVar(&releases, "releases", "", "a directory with one subdirectory per published release, named by its tag")
	f.StringVar(&withdrawn, "withdrawn", "", "the YAML list of withdrawn releases (release/withdrawn.yaml)")
	f.StringVar(&previous, "previous", "", "the feed index published before: the new sequence is its sequence plus one")
	f.Int64Var(&sequence, "sequence", 0, "the sequence, instead of --previous")
	f.StringVar(&generatedAt, "generated-at", "", "when the feed is generated, RFC 3339 (default now)")
	f.StringVar(&docs, "docs-url-template", "https://docs.sneakers-pam.com/v{version}/", "an entry's docs page, with {version} replaced by its version")
	f.StringVar(&out, "out", "", "the index file to write")
	for _, n := range []string{"channel", "release-key", "releases", "withdrawn", "out"} {
		_ = cmd.MarkFlagRequired(n)
	}
	return cmd
}

// feedSequence is the new feed's sequence: explicit, the previous feed's
// plus one, or 1 for the first feed.
func feedSequence(previous string, sequence int64, explicit bool, channel string) (int64, error) {
	switch {
	case previous != "" && explicit:
		return 0, errors.New("give --previous or --sequence, not both")
	case explicit:
		if sequence < 1 {
			return 0, fmt.Errorf("--sequence %d is not 1 or more", sequence)
		}
		return sequence, nil
	case previous == "":
		return 1, nil
	}
	b, err := os.ReadFile(previous) // #nosec G304 -- the feed published before
	if err != nil {
		return 0, err
	}
	var prev updatepkg.Index
	if err := json.Unmarshal(b, &prev); err != nil {
		return 0, fmt.Errorf("--previous %s doesn't parse: %w", previous, err)
	}
	if prev.Feed == nil || prev.Feed.Sequence < 1 {
		return 0, fmt.Errorf("--previous %s has no feed sequence", previous)
	}
	if prev.Feed.Channel != channel {
		return 0, fmt.Errorf("--previous %s is the %q feed, not %q", previous, prev.Feed.Channel, channel)
	}
	return prev.Feed.Sequence + 1, nil
}

// feedTagInChannel is whether a release tag belongs to the channel's feed.
func feedTagInChannel(tag, channel string) bool {
	pre := semver.Prerelease(tag)
	switch channel {
	case feedStable:
		return pre == ""
	default:
		return pre == "" || strings.HasPrefix(pre, "-rc.")
	}
}

// buildFeed verifies every release under dir with the release key, then
// merges the channel's releases, newest first, into one index. It returns
// the index (without the feed meta and the withdrawn list) and the tags it
// took.
func buildFeed(dir, channel, docs string, pub *ecdsa.PublicKey) (updatepkg.Index, []string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return updatepkg.Index{}, nil, err
	}
	var tags []string
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		if !semver.IsValid(e.Name()) {
			return updatepkg.Index{}, nil, fmt.Errorf("%s: the directory %q is not a release tag", dir, e.Name())
		}
		tags = append(tags, e.Name())
	}
	slices.SortFunc(tags, func(a, b string) int { return semver.Compare(b, a) })

	var merged updatepkg.Index
	var taken []string
	for _, tag := range tags {
		idx, err := verifiedRelease(filepath.Join(dir, tag), pub)
		if err != nil {
			return updatepkg.Index{}, nil, fmt.Errorf("release %s: %w", tag, err)
		}
		if !feedTagInChannel(tag, channel) {
			continue
		}
		tagRelease(&idx, tag, docs)
		merged = merged.Merge(idx)
		taken = append(taken, tag)
	}
	if len(taken) == 0 {
		return updatepkg.Index{}, nil, fmt.Errorf("%s has no release for the %s feed", dir, channel)
	}
	merged.Format = updatepkg.IndexFormat
	merged.Withdrawn = nil
	for _, list := range []*[]updatepkg.IndexEntry{&merged.Products, &merged.BaseOS, &merged.BaseWeb, &merged.Base} {
		slices.SortStableFunc(*list, func(a, b updatepkg.IndexEntry) int {
			if c := semver.Compare("v"+b.Version, "v"+a.Version); c != 0 {
				return c
			}
			return strings.Compare(a.File, b.File)
		})
	}
	return merged, taken, nil
}

// verifiedRelease reads a release directory's index after checking its
// signature, and its SHA256SUMS's, with the release key, and checks that
// every file the index lists has a size and a line in the SHA256SUMS.
func verifiedRelease(dir string, pub *ecdsa.PublicKey) (updatepkg.Index, error) {
	idxBytes, err := verifiedFile(dir, updatepkg.IndexName, pub)
	if err != nil {
		return updatepkg.Index{}, err
	}
	sums, err := verifiedFile(dir, "SHA256SUMS", pub)
	if err != nil {
		return updatepkg.Index{}, err
	}
	idx, err := updatepkg.ReadIndex(bytes.NewReader(idxBytes))
	if err != nil {
		return updatepkg.Index{}, err
	}
	listed := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		if _, name, ok := strings.Cut(sc.Text(), "  "); ok {
			listed[strings.TrimPrefix(name, "*")] = true
		}
	}
	for _, list := range [][]updatepkg.IndexEntry{idx.Products, idx.BaseOS, idx.BaseWeb, idx.Base} {
		for _, e := range list {
			switch {
			case e.File == "" || e.File != filepath.Base(e.File):
				return updatepkg.Index{}, fmt.Errorf("%s lists %q, which is not a file name", updatepkg.IndexName, e.File)
			case !listed[e.File]:
				return updatepkg.Index{}, fmt.Errorf("%s is not in SHA256SUMS", e.File)
			case e.Size <= 0:
				return updatepkg.Index{}, fmt.Errorf("%s has size %d in %s, want a positive size", e.File, e.Size, updatepkg.IndexName)
			}
		}
	}
	return idx, nil
}

// verifiedFile reads dir/name and checks its .sigstore.json bundle against
// the release key.
func verifiedFile(dir, name string, pub *ecdsa.PublicKey) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- a downloaded release file
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, name+".sigstore.json")) // #nosec G304 -- a downloaded release file
	if err != nil {
		return nil, err
	}
	bd, err := sigbundle.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s.sigstore.json: %w", name, err)
	}
	if err := bd.Verify(pub, sha256.Sum256(data)); err != nil {
		return nil, fmt.Errorf("%s doesn't verify with the release key: %w", name, err)
	}
	return data, nil
}

// tagRelease sets the tag and the docs page on every entry of a release's
// index.
func tagRelease(idx *updatepkg.Index, tag, docs string) {
	for _, list := range [][]updatepkg.IndexEntry{idx.Products, idx.BaseOS, idx.BaseWeb, idx.Base} {
		for i := range list {
			list[i].Tag = tag
			list[i].Docs = strings.ReplaceAll(docs, "{version}", list[i].Version)
		}
	}
}
