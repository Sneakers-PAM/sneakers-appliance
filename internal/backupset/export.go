// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package backupset

import (
	"archive/tar"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"filippo.io/age" // scrub:allow=fqdn -- a Go module path
	"filippo.io/age/agessh" // scrub:allow=fqdn -- a Go module path

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// Export writes the set to w as one tar encrypted to the box's recovery keys:
// nothing leaves the box in the clear, and the box can't read it back.
func (m *Manager) Export(ctx context.Context, name string, w io.Writer) (int64, error) {
	_, b, err := m.backups()
	if err != nil {
		return 0, err
	}
	mf, err := ReadManifest(b, name)
	if err != nil {
		return 0, err
	}
	if m.Recipients == nil {
		return 0, codes.New(codes.Backup, "this box has no recovery keys to encrypt to")
	}
	keys, err := m.Recipients()
	if err != nil {
		return 0, codes.Wrap(codes.Backup, err)
	}
	var to []age.Recipient
	for _, k := range keys {
		r, err := agessh.ParseRecipient(k)
		if err != nil {
			return 0, codes.Wrap(codes.Backup, err)
		}
		to = append(to, r)
	}
	if len(to) == 0 {
		return 0, codes.New(codes.Backup, "this box has no recovery keys to encrypt to")
	}
	cw := &counter{w: w}
	enc, err := age.Encrypt(cw, to...)
	if err != nil {
		return 0, codes.Wrap(codes.Backup, err)
	}
	tw := tar.NewWriter(enc)
	dir := filepath.Join(b.SetsHostDir(), name)
	paths := []string{ManifestFile}
	for _, f := range mf.Files {
		paths = append(paths, f.Path)
	}
	for _, rel := range paths {
		if err := ctx.Err(); err != nil {
			return cw.n, err
		}
		if err := addFile(tw, dir, rel); err != nil {
			return cw.n, codes.Wrap(codes.Backup, err)
		}
	}
	if err := errors.Join(tw.Close(), enc.Close()); err != nil {
		return cw.n, codes.Wrap(codes.Backup, err)
	}
	m.audit("product.backup.export", map[string]string{"set": name, "bytes": strconv.FormatInt(cw.n, 10)})
	return cw.n, nil
}

func addFile(tw *tar.Writer, dir, rel string) error {
	f, err := os.Open(filepath.Join(dir, filepath.FromSlash(rel))) // #nosec G304 -- a file the set's manifest names
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: rel, Mode: 0o600, Size: st.Size(), ModTime: st.ModTime().UTC(), Format: tar.FormatPAX}); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

type counter struct {
	w io.Writer
	n int64
}

func (c *counter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
