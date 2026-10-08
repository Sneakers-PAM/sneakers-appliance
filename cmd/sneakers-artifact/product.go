// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sigbundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

// productCheckCmd checks an unpacked product bundle the way the box does
// after it decrypts one: its k0s and images against its release.yaml, each
// image signed by the release key.
func productCheckCmd() *cobra.Command {
	var dir, key, arch string
	cmd := &cobra.Command{
		Use:   "product-check",
		Short: "Check an unpacked product bundle: k0s, the images and their signatures, and the stacks",
		RunE: func(cmd *cobra.Command, _ []string) error {
			pub, err := releaseKey(key)
			if err != nil {
				return err
			}
			rel, err := bundle.CheckProduct(os.DirFS(dir), arch, pub)
			if err != nil {
				return err
			}
			images, err := rel.Images()
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "checked product bundle %s: k0s %s, %d images\n", dir, rel.Spec.Kubernetes.K0s.Version, len(images))
			return err
		},
	}
	f := cmd.Flags()
	f.StringVar(&dir, "dir", "", "the unpacked product bundle")
	f.StringVar(&key, "release-key", "", "the release public key the images are signed with (cosign.pub)")
	f.StringVar(&arch, "arch", "amd64", "amd64 or arm64")
	_ = cmd.MarkFlagRequired("dir")
	_ = cmd.MarkFlagRequired("release-key")
	return cmd
}

// productIndexCmd writes the index a mirror or a release serves next to
// its product bundles. It reads only their headers: the box verifies each
// bundle when it's staged.
func productIndexCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "product-index <file.bin>...",
		Short: "Write sneakers-product-index.json for product bundles",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var idx updatepkg.Index
			for _, a := range args {
				e, err := indexEntry(a)
				if err != nil {
					return err
				}
				idx.Products = append(idx.Products, e)
			}
			b, err := json.MarshalIndent(idx, "", "  ")
			if err != nil {
				return err
			}
			if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil { // #nosec G306 G703 -- a public index
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), out)
			return err
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "the index file to write")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

func indexEntry(p string) (updatepkg.IndexEntry, error) {
	f, err := os.Open(p) // #nosec G304 -- a build output
	if err != nil {
		return updatepkg.IndexEntry{}, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return updatepkg.IndexEntry{}, err
	}
	pkg, err := updatepkg.Read(f, fi.Size())
	if err != nil {
		return updatepkg.IndexEntry{}, err
	}
	if !pkg.Header.IsProduct() {
		return updatepkg.IndexEntry{}, fmt.Errorf("%s isn't a product bundle", p)
	}
	return updatepkg.EntryOf(pkg.Header, fi.Size()), nil
}

func releaseKey(p string) (*ecdsa.PublicKey, error) {
	b, err := os.ReadFile(p) // #nosec G304 -- a public key file
	if err != nil {
		return nil, err
	}
	return sigbundle.ParsePublicKey(b)
}
