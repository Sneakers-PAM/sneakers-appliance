// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ReadFile reads settings netd wrote with WriteFile.
func ReadFile(path string) (Settings, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- netd's own settings file
	if err != nil {
		return Settings{}, err
	}
	// The file is YAML of the JSON form: the json tags are the ones that
	// leave out an unset address correctly (yaml.v3's omitempty can't see
	// into netip's types and drops set ones too).
	var doc any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return Settings{}, fmt.Errorf("network: %s doesn't parse: %w", path, err)
	}
	j, err := json.Marshal(doc)
	if err != nil {
		return Settings{}, fmt.Errorf("network: %s: %w", path, err)
	}
	var s Settings
	if err := json.Unmarshal(j, &s); err != nil {
		return Settings{}, fmt.Errorf("network: %s doesn't parse: %w", path, err)
	}
	return s, nil
}

// WriteFile writes s to path atomically (a temporary file, fsync, rename),
// making the directory when it's missing.
func WriteFile(path string, s Settings) error {
	j, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("network: %w", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(j, &doc); err != nil {
		return fmt.Errorf("network: %w", err)
	}
	clearStyle(&doc)
	b, err := yaml.Marshal(&doc)
	if err != nil {
		return fmt.Errorf("network: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("network: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("network: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("network: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("network: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("network: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("network: %w", err)
	}
	return nil
}

// clearStyle turns the JSON flow style YAML parsed into block style, so the
// file reads as ordinary YAML.
func clearStyle(n *yaml.Node) {
	n.Style = 0
	for _, c := range n.Content {
		clearStyle(c)
	}
}
