// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/mod/semver"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/ghrelease"
)

// releasePreviousCmd prints the release a release's patches are made from:
// the newest published one older than the tag on its channel, as a box on
// that channel would have picked it (ghrelease.Previous).
func releasePreviousCmd() *cobra.Command {
	var list, tag string
	cmd := &cobra.Command{
		Use:   "release-previous",
		Short: "Print the previous release on a tag's channel, from the GitHub API's releases list (nothing for the first)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if semver.Canonical(tag) != tag {
				return fmt.Errorf("%q isn't a release tag (v<major>.<minor>.<patch>[-pre])", tag)
			}
			b, err := os.ReadFile(list) // #nosec G304 -- a path the release job names
			if err != nil {
				return err
			}
			var rels []ghrelease.Release
			if err := json.Unmarshal(b, &rels); err != nil {
				return fmt.Errorf("the releases list doesn't parse: %w", err)
			}
			if r, ok := ghrelease.Previous(rels, tag); ok {
				_, err = fmt.Fprintln(cmd.OutOrStdout(), r.TagName)
			}
			return err
		},
	}
	cmd.Flags().StringVar(&list, "releases", "", "the releases list (GET /repos/<owner>/<repo>/releases)")
	cmd.Flags().StringVar(&tag, "tag", "", "the tag being released")
	_ = cmd.MarkFlagRequired("releases")
	_ = cmd.MarkFlagRequired("tag")
	return cmd
}
