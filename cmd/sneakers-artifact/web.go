// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/webslots"
)

// webPackCmd lays out a Base Web payload from built pages: pages/ and
// web.yaml, which the caller signs into web.yaml.sig before bin-pack
// --unit baseWeb packs the directory.
func webPackCmd() *cobra.Command {
	var pages, version, commit, needMin, needBefore, out string
	cmd := &cobra.Command{
		Use:   "web-pack",
		Short: "Lay out a Base Web payload (pages/ and web.yaml, to sign) from built :8443 pages",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := copyTree(pages, filepath.Join(out, webslots.PagesDir)); err != nil {
				return err
			}
			var need *updatepkg.Range
			if needMin != "" {
				need = &updatepkg.Range{Min: needMin, Before: needBefore}
			}
			m, err := webslots.WriteManifest(filepath.Join(out, webslots.PagesDir), version, commit, need)
			if err != nil {
				return err
			}
			p := filepath.Join(out, webslots.ManifestFile)
			if err := os.WriteFile(p, m, 0o644); err != nil { // #nosec G306 -- public
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), p)
			return err
		},
	}
	f := cmd.Flags()
	f.StringVar(&pages, "pages", "", "the built pages (apps/appliance-admin build/client)")
	f.StringVar(&version, "version", "", "the Base Web version")
	f.StringVar(&commit, "commit", "", "the short commit")
	f.StringVar(&needMin, "requires-baseos-min", "", "the oldest Base OS the pages fit (default: their own major.minor)")
	f.StringVar(&needBefore, "requires-baseos-before", "", "the first Base OS they no longer fit")
	f.StringVar(&out, "out", "", "the payload directory")
	for _, r := range []string{"pages", "version", "out"} {
		_ = cmd.MarkFlagRequired(r)
	}
	return cmd
}

// webCheckCmd loads a signed Base Web payload or slot the way
// sneakers-osadmin does.
func webCheckCmd() *cobra.Command {
	var dir, key string
	cmd := &cobra.Command{
		Use:   "web-check",
		Short: "Check a signed Base Web payload as :8443 loads it: the signature, every file's SHA-256, nothing unlisted",
		RunE: func(cmd *cobra.Command, _ []string) error {
			pub, err := releaseKey(key)
			if err != nil {
				return err
			}
			p, err := webslots.Load(dir, pub)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "checked Base Web %s: %d files\n", p.Manifest.Version, len(p.Manifest.Files))
			return err
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "the payload directory")
	cmd.Flags().StringVar(&key, "release-key", "", "the release public key (cosign.pub)")
	_ = cmd.MarkFlagRequired("dir")
	_ = cmd.MarkFlagRequired("release-key")
	return cmd
}

// copyTree copies the regular files under src to dst.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		to := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(to, 0o755) // #nosec G301 -- public pages
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s isn't a regular file", p)
		}
		in, err := os.Open(p) // #nosec G304 -- a build input
		if err != nil {
			return err
		}
		defer func() { _ = in.Close() }()
		o, err := os.Create(to) // #nosec G304 -- the payload directory
		if err != nil {
			return err
		}
		if _, err := io.Copy(o, in); err != nil {
			_ = o.Close()
			return err
		}
		return o.Close()
	})
}
