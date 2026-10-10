// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/brand"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sigbundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

// brandSummary describes the checked bundle's brand, with brand.Load's
// warnings (colours that fail the contrast check, so the base ones stay).
func brandSummary(dir string) (string, []string, error) {
	bdir := filepath.Join(dir, bundle.ProductBrand)
	if _, err := os.Stat(bdir); err != nil {
		return "no brand", nil, nil
	}
	b, warn, err := brand.Load(os.DirFS(bdir))
	if err != nil {
		return "", nil, err
	}
	var look string
	if b.Logo != nil {
		names, _ := fs.Glob(os.DirFS(bdir), "logo.*")
		look = fmt.Sprintf("%s (%s)", names[0], b.LogoType)
	}
	cols := "base colours"
	if c := b.Colours; c != nil {
		cols = fmt.Sprintf("colours %s %s %s", c.Background, c.Text, c.Accent)
	}
	if look == "" {
		return "brand: " + cols, warn, nil
	}
	return "brand: " + look + ", " + cols, warn, nil
}

// productCheckCmd checks an unpacked product bundle the way the box does
// after it decrypts one: its k0s and images against its release.yaml, each
// image signed by the release key.
func productCheckCmd() *cobra.Command {
	var dir, key, arch string
	cmd := &cobra.Command{
		Use:   "product-check",
		Short: "Check an unpacked product bundle: k0s, the images and their signatures, the stacks and the brand",
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
			look, warn, err := brandSummary(dir)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			for _, w := range warn {
				_, _ = fmt.Fprintf(out, "warning: %s\n", w)
			}
			_, err = fmt.Fprintf(out, "checked product bundle %s: k0s %s, %d images, %s\n", dir, rel.Spec.Kubernetes.K0s.Version, len(images), look)
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
// its .bin files (format 2): product bundles in its products section, the
// units' releases in baseOS and baseWeb, a base release from before the
// units in base, and with --bridge a Base OS release in base too, under
// its legacy name. Each file is listed by the name it has, which must be
// one its header gives (updatepkg.NamedFor). It reads only their headers:
// the box verifies each .bin when it's staged.
func productIndexCmd() *cobra.Command {
	var out string
	var bridges []string
	cmd := &cobra.Command{
		Use:     "product-index <file.bin>...",
		Aliases: []string{"index"},
		Short:   "Write sneakers-product-index.json for product bundles and base releases",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var idx updatepkg.Index
			for _, a := range args {
				h, size, err := indexHeader(a)
				if err != nil {
					return err
				}
				if err := idx.AddFile(h, size, filepath.Base(a)); err != nil {
					return err
				}
			}
			for _, a := range bridges {
				h, size, err := indexHeader(a)
				if err != nil {
					return err
				}
				if updatepkg.UnitOf(h) != updatepkg.UnitBaseOS || h.Kind != updatepkg.KindFull {
					return fmt.Errorf("%s isn't a Base OS full release; only one bridges", a)
				}
				idx.AddBridge(h, size)
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
	cmd.Flags().StringSliceVar(&bridges, "bridge", nil, "a Base OS full .bin to list in the legacy base section too (repeatable)")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

// binNameCmd prints the name a .bin is published under, read from its
// header; with --previous, the name the builds before the version-only
// names used, which a lab mirror also carries the file under so a box
// running one of those builds still finds it in the index.
func binNameCmd() *cobra.Command {
	var previous bool
	cmd := &cobra.Command{
		Use:   "bin-name <file.bin>",
		Short: "Print the name a .bin is published under",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			h, _, err := indexHeader(args[0])
			if err != nil {
				return err
			}
			name := updatepkg.FileName(h)
			if previous {
				name = updatepkg.PreviousFileName(h)
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), name)
			return err
		},
	}
	cmd.Flags().BoolVar(&previous, "previous", false, "the name before the version-only names")
	return cmd
}

// binInputsCmd prints the input digest a .bin's header carries
// (build/lab/units.sh inputs), so the .inputs written beside it is the one
// it was built with, never one worked out again.
func binInputsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "bin-inputs <file.bin>",
		Short: "Print the input digest a .bin's header carries",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			h, _, err := indexHeader(args[0])
			if err != nil {
				return err
			}
			if h.Inputs == "" {
				return fmt.Errorf("%s carries no input digest", args[0])
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), h.Inputs)
			return err
		},
	}
}

func indexHeader(p string) (updatepkg.Header, int64, error) {
	f, err := os.Open(p) // #nosec G304 -- a build output
	if err != nil {
		return updatepkg.Header{}, 0, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return updatepkg.Header{}, 0, err
	}
	pkg, err := updatepkg.Read(f, fi.Size())
	if err != nil {
		return updatepkg.Header{}, 0, err
	}
	return pkg.Header, fi.Size(), nil
}

func releaseKey(p string) (*ecdsa.PublicKey, error) {
	b, err := os.ReadFile(p) // #nosec G304 -- a public key file
	if err != nil {
		return nil, err
	}
	return sigbundle.ParsePublicKey(b)
}
