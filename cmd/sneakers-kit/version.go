// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
)

func newVersionCmd(pins release.Pins) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the kit version, its channel and the fingerprints it trusts",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fp := pins.Fingerprints()
			_, err := fmt.Fprintf(cmd.OutOrStdout(),
				"version: %s\nchannel: %s\nfingerprints (SHA-256):\n  release key: %s\n  db: %s\n  PK: %s\n  KEK: %s\n",
				release.Version, pins.Channel, fp.ReleaseKey, fp.DB, fp.PK, fp.KEK)
			return err
		},
	}
}
