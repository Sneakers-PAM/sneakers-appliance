// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"oras.land/oras-go/v2"
	orasoci "oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
)

// pushCmd copies the signed artifact, with its signature referrer, from its
// layout to a registry. Credentials come from REGISTRY_USERNAME and
// REGISTRY_PASSWORD, never from a flag.
func pushCmd() *cobra.Command {
	var dir, repoRef, tag string
	var plainHTTP bool
	cmd := &cobra.Command{
		Use:   "push",
		Short: "Push the signed artifact and its signature to a registry; print the index digest",
		RunE: func(cmd *cobra.Command, _ []string) error {
			src, err := orasoci.New(dir)
			if err != nil {
				return err
			}
			dst, err := remote.NewRepository(repoRef)
			if err != nil {
				return err
			}
			dst.PlainHTTP = plainHTTP
			if user := os.Getenv("REGISTRY_USERNAME"); user != "" {
				dst.Client = &auth.Client{
					Client:     retry.DefaultClient,
					Cache:      auth.NewCache(),
					Credential: auth.StaticCredential(dst.Reference.Registry, auth.Credential{Username: user, Password: os.Getenv("REGISTRY_PASSWORD")}),
				}
			}
			desc, err := oras.ExtendedCopy(cmd.Context(), src, tag, dst, tag, oras.DefaultExtendedCopyOptions)
			if err != nil {
				return fmt.Errorf("push %s:%s: %w", repoRef, tag, err)
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), desc.Digest)
			return err
		},
	}
	f := cmd.Flags()
	f.StringVar(&dir, "layout", "", "the signed artifact's layout")
	f.StringVar(&repoRef, "repo", "", "the repository, without a tag")
	f.StringVar(&tag, "tag", "", "the version tag (the layout's ref name)")
	f.BoolVar(&plainHTTP, "plain-http", false, "talk HTTP to a lab registry on loopback")
	for _, req := range []string{"layout", "repo", "tag"} {
		_ = cmd.MarkFlagRequired(req)
	}
	return cmd
}
