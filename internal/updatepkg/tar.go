// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package updatepkg

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// TarDir writes dir as an uncompressed tar with fixed owners, modes and
// times, so the same tree always gives the same bytes. Only directories and
// regular files are allowed.
func TarDir(dir string, w io.Writer) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("updatepkg: %w", err)
	}
	defer func() { _ = root.Close() }()
	tw := tar.NewWriter(w)
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil || rel == "." {
			return err
		}
		h := &tar.Header{Name: filepath.ToSlash(rel), ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}
		switch {
		case d.IsDir():
			h.Typeflag, h.Name, h.Mode = tar.TypeDir, h.Name+"/", 0o755
			return tw.WriteHeader(h)
		case d.Type().IsRegular():
			fi, err := d.Info()
			if err != nil {
				return err
			}
			h.Typeflag, h.Mode, h.Size = tar.TypeReg, 0o644, fi.Size()
			if err := tw.WriteHeader(h); err != nil {
				return err
			}
			f, err := root.Open(rel)
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			_, err = io.Copy(tw, f)
			return err
		default:
			return fmt.Errorf("%s is neither a directory nor a regular file", rel)
		}
	})
	if err != nil {
		return fmt.Errorf("updatepkg: %w", err)
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("updatepkg: %w", err)
	}
	return nil
}

// Untar unpacks a tar made by TarDir into dir. A path outside dir, or an
// entry other than a directory or a regular file, is UPGRADE_FORMAT.
func Untar(r io.Reader, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- the unpacked release is world-readable, like the root image
		return fmt.Errorf("updatepkg: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("updatepkg: %w", err)
	}
	defer func() { _ = root.Close() }()
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return codes.New(codes.UpgradeFormat, "the payload isn't a readable tar: %v", err)
		}
		name := filepath.FromSlash(h.Name)
		if !filepath.IsLocal(name) {
			return codes.New(codes.UpgradeFormat, "the payload names %q, outside its directory", h.Name)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, 0o755); err != nil {
				return fmt.Errorf("updatepkg: %w", err)
			}
		case tar.TypeReg:
			if err := writeFile(root, name, tr, h.Size); err != nil {
				return err
			}
		default:
			return codes.New(codes.UpgradeFormat, "the payload entry %q is neither a directory nor a regular file", h.Name)
		}
	}
}

func writeFile(root *os.Root, name string, r io.Reader, size int64) error {
	if err := root.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		return fmt.Errorf("updatepkg: %w", err)
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("updatepkg: %w", err)
	}
	if _, err := io.CopyN(f, r, size); err != nil {
		_ = f.Close()
		return fmt.Errorf("updatepkg: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("updatepkg: %w", err)
	}
	return nil
}
