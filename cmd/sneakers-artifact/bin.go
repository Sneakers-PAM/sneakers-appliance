// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/product"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sigbundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

// The files bin-pack leaves for the sign step and bin-seal.
const (
	headerFile  = "header.json"
	payloadFile = "payload.age"
)

// labUpdateKeyCmd makes a throwaway lab update key pair. A production key is
// made by the owner (docs/runbooks/production-keys.md), never by this.
func labUpdateKeyCmd() *cobra.Command {
	var out, name string
	cmd := &cobra.Command{
		Use:   "lab-update-key",
		Short: "Write a throwaway lab update key (<name>.key) and its recipient (<name>.pub)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			id, err := age.GenerateX25519Identity()
			if err != nil {
				return err
			}
			if err := os.MkdirAll(out, 0o700); err != nil {
				return err
			}
			const label = "# Sneakers-PAM LAB ephemeral NOT FOR PRODUCTION update key\n"
			if err := os.WriteFile(filepath.Join(out, name+".key"), []byte(label+id.String()+"\n"), 0o600); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(out, name+".pub"), []byte(label+id.Recipient().String()+"\n"), 0o644); err != nil { // #nosec G306 -- a public recipient
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "wrote a lab update key to", out)
			return err
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "the key directory")
	cmd.Flags().StringVar(&name, "name", "update", "the key files' base name")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

func binPackCmd() *cobra.Command {
	var (
		h                      updatepkg.Header
		kind, unit             string
		needMin, needBefore    string
		layout, recipient, out string
	)
	cmd := &cobra.Command{
		Use:   "bin-pack",
		Short: "Encrypt a signed artifact layout into an update package's payload and write the header to sign",
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := readRecipient(recipient)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(out, 0o755); err != nil { // #nosec G301 -- release outputs are public
				return err
			}
			var payload bytes.Buffer
			if err := updatepkg.TarDir(layout, &payload); err != nil {
				return err
			}
			ct, err := os.Create(filepath.Join(out, payloadFile)) // #nosec G304 -- the work directory
			if err != nil {
				return err
			}
			h.Kind, h.Unit = updatepkg.Kind(kind), updatepkg.Unit(unit)
			if needMin != "" || needBefore != "" {
				h.Requires = map[updatepkg.Unit]updatepkg.Range{updatepkg.UnitBaseOS: {Min: needMin, Before: needBefore}}
			}
			h, err = updatepkg.Encrypt(&payload, h, r, ct)
			if cerr := ct.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
			b, err := h.Marshal()
			if err != nil {
				return err
			}
			p := filepath.Join(out, headerFile)
			if err := os.WriteFile(p, b, 0o644); err != nil { // #nosec G306 -- the header is public
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), p)
			return err
		},
	}
	f := cmd.Flags()
	f.StringVar(&layout, "layout", "", "the signed artifact's OCI layout, or the unpacked product bundle")
	f.StringVar(&recipient, "recipient", "", "the channel's update key recipient (age)")
	f.StringVar(&h.Version, "version", "", "release version")
	f.StringVar(&h.Arch, "arch", "amd64", "amd64 or arm64")
	f.StringVar(&h.Channel, "channel", release.ChannelLab, "production or lab")
	f.StringVar(&kind, "kind", string(updatepkg.KindFull), "full, patch or product")
	f.StringSliceVar(&h.Bases, "base", nil, "a base version a patch applies to (repeatable); for a product bundle, an exact base for boxes that predate --min-base")
	f.StringVar(&h.MinBase, "min-base", "", "the oldest base version a product bundle fits (inclusive)")
	f.StringVar(&h.MaxBase, "max-base", "", "the newest base version a product bundle fits (inclusive; optional)")
	f.StringVar(&unit, "unit", "", "baseOS or baseWeb (empty: a base release named as before the units)")
	f.StringVar(&h.Commit, "commit", "", "the short commit the package is built from; the file name carries it")
	f.IntVar(&h.Epoch, "epoch", 0, "the signing-key epoch (0 leaves it out, which reads as 1)")
	f.StringVar(&h.Inputs, "inputs", "", "the SHA-256 of the unit's build inputs (units.sh inputs)")
	f.StringVar(&needMin, "requires-baseos-min", "", "a Base Web package: the oldest Base OS it fits (default: its own major.minor)")
	f.StringVar(&needBefore, "requires-baseos-before", "", "a Base Web package: the first Base OS it no longer fits")
	f.StringVar(&out, "out", "", "the work directory for header.json and payload.age")
	for _, req := range []string{"layout", "recipient", "version", "out"} {
		_ = cmd.MarkFlagRequired(req)
	}
	return cmd
}

func binSealCmd() *cobra.Command {
	var work, bundle, out string
	var bridge bool
	cmd := &cobra.Command{
		Use:   "bin-seal",
		Short: "Join the header, its signature bundle and the payload into the .bin",
		RunE: func(cmd *cobra.Command, _ []string) error {
			hdr, err := os.ReadFile(filepath.Join(work, headerFile)) // #nosec G304 -- the work directory
			if err != nil {
				return err
			}
			bd, err := os.ReadFile(bundle) // #nosec G304 -- the bundle cosign wrote
			if err != nil {
				return err
			}
			prefix := sealedPrefix(hdr, bd)
			p, err := updatepkg.Read(bytes.NewReader(prefix), int64(len(prefix)))
			if err != nil {
				return err
			}
			ct, err := os.Open(filepath.Join(work, payloadFile)) // #nosec G304 -- the work directory
			if err != nil {
				return err
			}
			defer func() { _ = ct.Close() }()
			if err := os.MkdirAll(out, 0o755); err != nil { // #nosec G301 -- release outputs are public
				return err
			}
			dst := filepath.Join(out, updatepkg.FileName(p.Header))
			f, err := os.Create(dst) // #nosec G304 -- the output directory
			if err != nil {
				return err
			}
			if err := updatepkg.Seal(f, hdr, bd, ct); err != nil {
				_ = f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			if bridge {
				if err := copyBridge(dst, p.Header, out); err != nil {
					return err
				}
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), dst)
			return err
		},
	}
	cmd.Flags().BoolVar(&bridge, "bridge", false, "a Base OS full release: also write the same file under the name a box from before the units fetches")
	cmd.Flags().StringVar(&work, "work", "", "the work directory bin-pack wrote")
	cmd.Flags().StringVar(&bundle, "bundle", "", "the signature bundle over header.json")
	cmd.Flags().StringVar(&out, "out", "", "the output directory")
	for _, req := range []string{"work", "bundle", "out"} {
		_ = cmd.MarkFlagRequired(req)
	}
	return cmd
}

// copyBridge writes the sealed Base OS file dst a second time under its
// legacy name (the bytes are the same; the name isn't signed).
func copyBridge(dst string, h updatepkg.Header, out string) error {
	if updatepkg.UnitOf(h) != updatepkg.UnitBaseOS || h.Kind != updatepkg.KindFull || h.Unit == "" {
		return fmt.Errorf("only a Base OS full release (bin-pack --unit baseOS) has a bridge copy")
	}
	src, err := os.Open(dst) // #nosec G304 -- the file just sealed
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	b, err := os.Create(filepath.Join(out, updatepkg.LegacyFileName(h))) // #nosec G304 -- the output directory
	if err != nil {
		return err
	}
	if _, err := io.Copy(b, src); err != nil {
		_ = b.Close()
		return err
	}
	return b.Close()
}

// sealedPrefix is the package without its payload, enough to read the
// header back for the file name.
func sealedPrefix(hdr, bd []byte) []byte {
	var b bytes.Buffer
	_ = updatepkg.Seal(&b, hdr, bd, bytes.NewReader(nil))
	return b.Bytes()
}

func binVerifyCmd() *cobra.Command {
	var key, channel, identity, identityUKI, extract string
	cmd := &cobra.Command{
		Use:   "bin-verify <file.bin>",
		Short: "Verify a .bin's signature, channel and payload digest; with --identity or --identity-uki also decrypt it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pub, err := os.ReadFile(key) // #nosec G304 -- a public key file
			if err != nil {
				return err
			}
			f, err := os.Open(args[0])
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			fi, err := f.Stat()
			if err != nil {
				return err
			}
			p, err := updatepkg.Read(f, fi.Size())
			if err != nil {
				return err
			}
			if err := p.Verify(pub, channel); err != nil {
				return err
			}
			if identity != "" || identityUKI != "" {
				var id age.Identity
				if identity != "" {
					id, err = readIdentity(identity)
				} else {
					id, err = ukiIdentity(identityUKI)
				}
				if err != nil {
					return err
				}
				pr, pw := io.Pipe()
				done := make(chan error, 1)
				go func() {
					var err error
					if extract != "" {
						err = updatepkg.Untar(pr, extract)
					}
					if err == nil {
						_, err = io.Copy(io.Discard, pr)
					}
					// A failed unpack stops the decrypt's writes too.
					_ = pr.CloseWithError(err)
					done <- err
				}()
				err = p.Decrypt(id, pw)
				_ = pw.CloseWithError(err)
				if uerr := <-done; err == nil {
					err = uerr
				}
				if err != nil {
					return err
				}
				// The box checks an unpacked product bundle before it uses it.
				if extract != "" && p.Header.IsProduct() {
					key, err := sigbundle.ParsePublicKey(pub)
					if err != nil {
						return err
					}
					if err := product.Finish(extract, p.Header.Arch, key); err != nil {
						return err
					}
				}
			}
			h := p.Header
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "verified %s %s %s %s (%s)\n", h.Name, h.Version, h.Arch, h.Kind, h.Channel)
			return err
		},
	}
	f := cmd.Flags()
	f.StringVar(&key, "release-key", "", "the channel's release public key (cosign.pub)")
	f.StringVar(&channel, "channel", "", "production or lab")
	f.StringVar(&identity, "identity", "", "the update key, to also decrypt (lab runs)")
	f.StringVar(&identityUKI, "identity-uki", "", "a UKI whose update key decrypts, as the box does")
	f.StringVar(&extract, "extract", "", "with --identity or --identity-uki, unpack the payload here")
	cmd.MarkFlagsMutuallyExclusive("identity", "identity-uki")
	_ = cmd.MarkFlagRequired("release-key")
	_ = cmd.MarkFlagRequired("channel")
	return cmd
}

func readRecipient(p string) (*age.X25519Recipient, error) {
	f, err := os.Open(p) // #nosec G304 -- a public recipient file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	rs, err := age.ParseRecipients(f)
	if err != nil {
		return nil, err
	}
	if len(rs) != 1 {
		return nil, fmt.Errorf("%s holds %d recipients; the update key is exactly one", p, len(rs))
	}
	x, ok := rs[0].(*age.X25519Recipient)
	if !ok {
		return nil, fmt.Errorf("%s isn't an age X25519 recipient", p)
	}
	return x, nil
}

func readIdentity(p string) (age.Identity, error) {
	f, err := os.Open(p) // #nosec G304 -- the lab run's key directory
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, err
	}
	if len(ids) != 1 {
		return nil, fmt.Errorf("%s holds %d identities; want one", p, len(ids))
	}
	return ids[0], nil
}
