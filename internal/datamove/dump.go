// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package datamove

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

const (
	manifestFile = "manifest.json"
	rolesFile    = "roles.sql"
)

// Part is one file of a dump.
type Part struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// dumpedDB is one database of a dump, with the row count of every table as
// the source held it, with the services stopped.
type dumpedDB struct {
	Name string `json:"name"`
	Part
	Rows map[string]int64 `json:"rows"`
}

// manifest lists a dump. It holds names, sizes and counts, no data.
type manifest struct {
	Roles     Part       `json:"roles"`
	Databases []dumpedDB `json:"databases"`
}

// dump writes the roles and every database to the backup partition. The
// directory is cleared first: it only ever holds the latest attempt's dump.
func (m *Move) dump(ctx context.Context) (*manifest, error) {
	dir := m.dumpDir()
	if err := os.RemoveAll(dir); err != nil {
		return nil, fmt.Errorf("clearing the last dump: %w", err)
	}
	return m.writeDump(ctx, m.Spec.Source, dir, m.Spec.Databases, "Saving")
}

// writeDump writes c's roles and dbs to the new directory dir, each with its
// checksum and row counts. The manifest goes last, so a dump that has one is
// whole.
func (m *Move) writeDump(ctx context.Context, c productspec.DataCluster, dir string, dbs []string, verb string) (*manifest, error) {
	// The roles file holds password verifiers, so nothing here is for
	// anyone but root, even on the encrypted partition.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("making the dump's directory: %w", err)
	}
	man := &manifest{}
	m.say("%s the roles", verb)
	p, err := m.toFile(dir, rolesFile, func(w io.Writer) error { return m.Engine.DumpRoles(ctx, c, w) })
	if err != nil {
		return nil, fmt.Errorf("saving the roles: %w", err)
	}
	man.Roles = p
	for i, db := range dbs {
		m.say("%s %s (%d of %d)", verb, db, i+1, len(dbs))
		p, err := m.toFile(dir, db+".dump", func(w io.Writer) error { return m.Engine.DumpDatabase(ctx, c, db, w) })
		if err != nil {
			return nil, fmt.Errorf("saving %s: %w", db, err)
		}
		rows, err := m.Engine.Counts(ctx, c, db)
		if err != nil {
			return nil, fmt.Errorf("counting %s: %w", db, err)
		}
		man.Databases = append(man.Databases, dumpedDB{Name: db, Part: p, Rows: rows})
		m.logger().Info("datamove: saved", log.F("database", db), log.F("bytes", p.Bytes), log.F("tables", len(rows)))
	}
	b, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("writing the manifest: %w", err)
	}
	if err := writeSynced(filepath.Join(dir, manifestFile), b); err != nil {
		return nil, fmt.Errorf("writing the manifest: %w", err)
	}
	return man, syncDir(dir)
}

func (m *Move) toFile(dir, name string, write func(io.Writer) error) (p Part, err error) {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- the move's own dump
	if err != nil {
		return Part{}, err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	h := sha256.New()
	c := &counter{w: f, h: h}
	if err := write(c); err != nil {
		return Part{}, err
	}
	if err := f.Sync(); err != nil {
		return Part{}, err
	}
	return Part{File: name, SHA256: hex.EncodeToString(h.Sum(nil)), Bytes: c.n}, nil
}

type counter struct {
	w io.Writer
	h hash.Hash
	n int64
}

func (c *counter) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	c.h.Write(b[:n])
	c.n += int64(n)
	return n, err
}

// verifyDump reads every file back from the partition and compares its
// checksum, so what's restored is what was dumped.
func (m *Move) verifyDump(dir string, man *manifest) error {
	m.say("Checking the dump")
	parts := []Part{man.Roles}
	for _, db := range man.Databases {
		parts = append(parts, db.Part)
	}
	for _, p := range parts {
		sum, err := sumFile(filepath.Join(dir, p.File))
		if err != nil {
			return fmt.Errorf("reading the dump: %w", err)
		}
		if sum != p.SHA256 {
			return fmt.Errorf("the dump's %s doesn't match its checksum", p.File)
		}
	}
	return nil
}

func sumFile(p string) (string, error) {
	f, err := os.Open(p) // #nosec G304 -- the move's own dump
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readManifest(dir string) (*manifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, manifestFile)) // #nosec G304 -- the move's own dump
	if err != nil {
		return nil, err
	}
	man := &manifest{}
	return man, json.Unmarshal(b, man)
}
