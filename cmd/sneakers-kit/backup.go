// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import "github.com/spf13/cobra"

// newBackupCmd is the backup command group. Its commands (reading an
// exported backup set off-box) arrive with the backups work; until then it
// prints its usage.
func newBackupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "backup",
		Short: "Work with exported backup sets off the box",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
}
