// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strings"

	log "github.com/Bugs5382/go-log"
	"github.com/spf13/cobra"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/kitout"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verify"
)

// DefaultRepository is where the org publishes sneakers-os.
const DefaultRepository = "ghcr.io/sneakers-pam/sneakers-os"

// sourceFor reads a <ref>: an existing directory is an OCI layout (offline
// sites); "sneakers-os:<version>" or a bare "sha256:..." digest is the org
// repository; anything else is a full registry reference.
func sourceFor(ref string, plainHTTP bool) (verify.Source, error) {
	if st, err := os.Stat(ref); err == nil && st.IsDir() {
		return verify.LocalLayout(ref), nil
	}
	o := verify.RegistryOptions{PlainHTTP: plainHTTP}
	switch {
	case strings.HasPrefix(ref, "sneakers-os:"):
		return verify.Registry(DefaultRepository+":"+strings.TrimPrefix(ref, "sneakers-os:"), o), nil
	case strings.HasPrefix(ref, "sha256:"):
		return verify.Registry(DefaultRepository+"@"+ref, o), nil
	case strings.Contains(ref, "/"):
		return verify.Registry(ref, o), nil
	}
	return nil, fmt.Errorf("%q is neither a layout directory, sneakers-os:<version>, a digest nor a registry reference", ref)
}

func newLogger(cmd *cobra.Command) log.Logger {
	return log.NewLoggerWithOptions("sneakers-kit", log.WithOutput(cmd.ErrOrStderr()), log.WithDefaultFormat(log.FormatConsole), log.WithDefaultLevel(log.LevelInfo))
}

func newVerifyCmd(pins release.Pins) *cobra.Command {
	var (
		plainHTTP bool
		arch      string
	)
	cmd := &cobra.Command{
		Use:   "verify <ref>",
		Short: "Verify the whole chain of a release; writes nothing",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			src, err := sourceFor(args[0], plainHTTP)
			if err != nil {
				return err
			}
			m, err := kitout.Verify(cmd.Context(), src, pins, kitout.Options{Arch: arch, KitVersion: release.Version, Logger: newLogger(cmd)})
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "verified %s %s (%s)\n", m.Metadata.Version, m.Spec.Arch, m.Metadata.Channel)
			return err
		},
	}
	cmd.Flags().StringVar(&arch, "arch", "amd64", "architecture: amd64 or arm64")
	cmd.Flags().BoolVar(&plainHTTP, "plain-http", false, "talk plain HTTP to the registry (a lab registry on loopback only)")
	return cmd
}

func newBuildCmd(pins release.Pins, writers kitout.Writers) *cobra.Command {
	var (
		format, arch, diskSize, out string
		plainHTTP                   bool
	)
	cmd := &cobra.Command{
		Use:   "build <ref>",
		Short: "Verify a release, then build install media from exactly the verified bytes",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			src, err := sourceFor(args[0], plainHTTP)
			if err != nil {
				return err
			}
			size, err := parseSize(diskSize)
			if err != nil {
				return err
			}
			paths, err := writers.Run(cmd.Context(), src, pins, format, kitout.Options{
				Out: out, Arch: arch, DiskSize: size, KitVersion: release.Version, Logger: newLogger(cmd),
			})
			if err != nil {
				return err
			}
			for _, p := range paths {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), p)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "", "output format: iso, ova, qcow2, rpi or raw")
	cmd.Flags().StringVar(&arch, "arch", "amd64", "architecture: amd64 or arm64 (rpi is arm64; iso, ova and qcow2 are amd64)")
	cmd.Flags().StringVar(&diskSize, "disk-size", "64G", "size of the installed disk image, at least 64G (32G for rpi)")
	cmd.Flags().StringVar(&out, "out", ".", "directory the output is written to")
	cmd.Flags().BoolVar(&plainHTTP, "plain-http", false, "talk plain HTTP to the registry (a lab registry on loopback only)")
	_ = cmd.MarkFlagRequired("format")
	return cmd
}

// parseSize reads 64G, 100G, 2T or a byte count.
func parseSize(s string) (int64, error) {
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "T"):
		mult, s = 1<<40, strings.TrimSuffix(s, "T")
	case strings.HasSuffix(s, "G"):
		mult, s = 1<<30, strings.TrimSuffix(s, "G")
	case strings.HasSuffix(s, "M"):
		mult, s = 1<<20, strings.TrimSuffix(s, "M")
	}
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil || n <= 0 || n > (1<<62)/mult {
		return 0, fmt.Errorf("--disk-size %q isn't a size like 64G", s)
	}
	return n * mult, nil
}
