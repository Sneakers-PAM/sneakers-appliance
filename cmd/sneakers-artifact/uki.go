// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/ukikey"
)

// ukiAddKeyCmd adds the channel's update key to an unsigned UKI as its
// .updkey section, for the db key to sign next. The key must belong to the
// committed recipient the .bin is encrypted to, so a box never boots with a
// key that can't open its own channel's packages.
func ukiAddKeyCmd() *cobra.Command {
	var uki, key, recipient, out string
	cmd := &cobra.Command{
		Use:   "uki-add-key",
		Short: "Add the update key to an unsigned UKI (before it's signed)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			want, err := readRecipient(recipient)
			if err != nil {
				return err
			}
			kb, err := os.ReadFile(key) // #nosec G304 -- the sign step's tmpfs or a lab key directory
			if err != nil {
				return err
			}
			id, err := readIdentity(key)
			if err != nil {
				return err
			}
			x, ok := id.(*age.X25519Identity)
			if !ok || x.Recipient().String() != want.String() {
				return fmt.Errorf("the update key doesn't belong to %s", recipient)
			}
			img, err := os.ReadFile(uki) // #nosec G304 -- a build input
			if err != nil {
				return err
			}
			keyed, err := ukikey.Embed(img, kb)
			if err != nil {
				return err
			}
			if err := os.WriteFile(out, keyed, 0o600); err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), out)
			return err
		},
	}
	f := cmd.Flags()
	f.StringVar(&uki, "uki", "", "the unsigned UKI")
	f.StringVar(&key, "key", "", "the update key (an age identity file)")
	f.StringVar(&recipient, "recipient", "", "the channel's committed update key recipient (update.pub)")
	f.StringVar(&out, "out", "", "the UKI with the key, to sign")
	for _, req := range []string{"uki", "key", "recipient", "out"} {
		_ = cmd.MarkFlagRequired(req)
	}
	return cmd
}

func ukiIdentity(p string) (age.Identity, error) {
	f, err := os.Open(p) // #nosec G304 -- a UKI to read the key from
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return ukikey.Identity(f)
}
