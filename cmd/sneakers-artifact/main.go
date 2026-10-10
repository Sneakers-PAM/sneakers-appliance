// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command sneakers-artifact assembles the sneakers-os artifact from built
// release files, attaches a signature made elsewhere, and packs the signed
// artifact into the encrypted update package (the .bin). It holds no signing
// key: the release workflow's sign job (or a lab build, with its throwaway
// key) signs the index blob and the .bin header with `cosign sign-blob
// --bundle` and hands the bundles back to `attach` and `bin-seal`. The only
// key it makes is a throwaway lab update key. `uki-add-key` puts the update
// key the sign step hands it into the unsigned UKI, before the db key signs
// it, so the box can decrypt its channel's packages.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/artifact"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/oci"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verify"
)

func main() {
	if err := root().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "sneakers-artifact:", err)
		os.Exit(1)
	}
}

func root() *cobra.Command {
	r := &cobra.Command{Use: "sneakers-artifact", Short: "Assemble the sneakers-os artifact, attach its signature and pack the update package", SilenceUsage: true}
	r.AddCommand(assembleCmd(), indexBlobCmd(), attachCmd(), labUpdateKeyCmd(), ukiAddKeyCmd(), binPackCmd(), binSealCmd(), binVerifyCmd(), productCheckCmd(), productIndexCmd(), binNameCmd(), binInputsCmd(), pushCmd(), patchMakeCmd(), patchCheckCmd(), webPackCmd(), webCheckCmd(), releasePreviousCmd())
	return r
}

func assembleCmd() *cobra.Command {
	var (
		in                         artifact.Input
		releaseF, releaseSig, root string
		verityJSON, uki, loader    string
		keysDir, pk, kek, db, out  string
	)
	cmd := &cobra.Command{
		Use:   "assemble",
		Short: "Write an unsigned artifact as an OCI layout",
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := os.ReadFile(verityJSON) // #nosec G304 -- a build input
			if err != nil {
				return err
			}
			var v struct {
				RootHash   string `json:"roothash"`
				HashOffset int64  `json:"hashOffset"`
			}
			if err := json.Unmarshal(b, &v); err != nil {
				return fmt.Errorf("%s: %w", verityJSON, err)
			}
			in.RootHash, in.HashOffset = v.RootHash, v.HashOffset
			in.Release, in.ReleaseSig, in.Root = artifact.File{Path: releaseF}, artifact.File{Path: releaseSig}, artifact.File{Path: root}
			if in.Arch == "amd64" {
				in.UKI, in.Loader = artifact.File{Path: uki}, artifact.File{Path: loader}
				in.Keys = map[string]artifact.File{}
				for _, name := range verify.SecureBootFiles {
					in.Keys[name] = artifact.File{Path: filepath.Join(keysDir, name)}
				}
				for _, c := range []struct {
					path string
					dst  *string
				}{{pk, &in.Fingerprints.PK}, {kek, &in.Fingerprints.KEK}, {db, &in.Fingerprints.DB}} {
					p, err := os.ReadFile(c.path) // #nosec G304 -- a build input
					if err != nil {
						return err
					}
					if *c.dst = release.Fingerprint(p); *c.dst == "" {
						return fmt.Errorf("%s holds no PEM certificate", c.path)
					}
				}
			}
			idx, err := artifact.Write(out, in, nil)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), idx.Digest)
			return err
		},
	}
	f := cmd.Flags()
	f.StringVar(&in.Arch, "arch", "amd64", "amd64 or arm64")
	f.StringVar(&in.Version, "version", "", "release version")
	f.StringVar(&in.Channel, "channel", release.ChannelLab, "production or lab")
	f.StringVar(&in.KitMin, "kit-min", artifact.DefaultKitMin, "the oldest kit or init version that may verify this release (spec.kitMin)")
	f.StringVar(&in.Systemd, "systemd", "", "systemd-boot version")
	f.StringVar(&releaseF, "release", "", "release.yaml")
	f.StringVar(&releaseSig, "release-sig", "", "release.yaml's signature bundle")
	f.StringVar(&root, "root", "", "root image")
	f.StringVar(&verityJSON, "verity-json", "", "verity.json from the root build")
	f.StringVar(&uki, "uki", "", "signed UKI (amd64)")
	f.StringVar(&loader, "loader", "", "signed systemd-boot (amd64)")
	f.StringVar(&keysDir, "keys", "", "directory with PK.auth ... dbx.esl (amd64)")
	f.StringVar(&pk, "pk-cert", "", "PK certificate (PEM)")
	f.StringVar(&kek, "kek-cert", "", "KEK certificate (PEM)")
	f.StringVar(&db, "db-cert", "", "db certificate (PEM)")
	f.StringVar(&out, "out", "", "the new layout's directory")
	for _, req := range []string{"version", "release", "release-sig", "root", "verity-json", "out"} {
		_ = cmd.MarkFlagRequired(req)
	}
	return cmd
}

// indexBlobCmd prints the path of the artifact's index blob: what's signed.
func indexBlobCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "index-blob",
		Short: "Print the path of the index blob to sign",
		RunE: func(cmd *cobra.Command, _ []string) error {
			l, idx, err := artifactIndex(dir)
			if err != nil {
				return err
			}
			p, err := l.BlobPath(idx.Digest)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), p)
			return err
		},
	}
	cmd.Flags().StringVar(&dir, "layout", "", "the artifact's layout")
	_ = cmd.MarkFlagRequired("layout")
	return cmd
}

func attachCmd() *cobra.Command {
	var dir, bundle string
	cmd := &cobra.Command{
		Use:   "attach",
		Short: "Attach a signature bundle over the index blob",
		RunE: func(_ *cobra.Command, _ []string) error {
			l, idx, err := artifactIndex(dir)
			if err != nil {
				return err
			}
			b, err := os.ReadFile(bundle) // #nosec G304 -- the bundle cosign wrote
			if err != nil {
				return err
			}
			return artifact.AttachSignature(l, idx, b)
		},
	}
	cmd.Flags().StringVar(&dir, "layout", "", "the artifact's layout")
	cmd.Flags().StringVar(&bundle, "bundle", "", "the signature bundle")
	_ = cmd.MarkFlagRequired("layout")
	_ = cmd.MarkFlagRequired("bundle")
	return cmd
}

func artifactIndex(dir string) (*oci.Layout, ocispec.Descriptor, error) {
	l, err := oci.Open(dir)
	if err != nil {
		return nil, ocispec.Descriptor{}, err
	}
	top, err := l.Index()
	if err != nil {
		return nil, ocispec.Descriptor{}, err
	}
	for _, d := range top.Manifests {
		if d.MediaType == ocispec.MediaTypeImageIndex {
			return l, d, nil
		}
	}
	return nil, ocispec.Descriptor{}, fmt.Errorf("%s holds no image index", dir)
}
