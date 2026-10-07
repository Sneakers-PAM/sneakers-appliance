// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package accessapi is what accessd's callers share with it: the socket,
// the headers a caller sends, the status cache it keeps for when it is
// down, and the sentence they show then. It links no program runner, so
// the closed shell can use it.
package accessapi

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
)

// SocketPath is where accessd listens.
const SocketPath = "/run/sneakers/access.sock"

// ReadyFile appears once accessd serves its socket.
const ReadyFile = "/run/sneakers/access.ready"

// StatusFile is where accessd keeps the last status.
const StatusFile = "/run/sneakers/access/status.json"

// The headers a closed-shell login sends with each call. Both are only
// for the audit entry: the identity is the peer uid, and a fingerprint
// that isn't one of that admin's keys is refused.
const (
	KeyHeader    = "Sneakers-Key-Fingerprint"
	SourceHeader = "Sneakers-Source"
)

// ClientHeader carries the browser's address from sneakers-osadmin.
// accessd reads it from the osadmin uid only.
const ClientHeader = "Sneakers-Client-Address"

// Unavailable is what the shell and :8443 say while accessd is down.
const Unavailable = "the appliance services are unavailable; try again shortly"

// StatusCache is the last status accessd computed and when.
type StatusCache struct {
	Saved  time.Time
	Status *osadminv1.GetStatusResponse
}

type cacheFile struct {
	Saved  time.Time       `json:"saved"`
	Status json.RawMessage `json:"status"`
}

// ReadStatusCache reads the status accessd last kept at path.
func ReadStatusCache(path string) (StatusCache, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the status file's fixed path
	if err != nil {
		return StatusCache{}, fmt.Errorf("status cache: %w", err)
	}
	var f cacheFile
	if err := json.Unmarshal(b, &f); err != nil {
		return StatusCache{}, fmt.Errorf("status cache: %w", err)
	}
	st := &osadminv1.GetStatusResponse{}
	if err := protojson.Unmarshal(f.Status, st); err != nil {
		return StatusCache{}, fmt.Errorf("status cache: %w", err)
	}
	return StatusCache{Saved: f.Saved, Status: st}, nil
}

// WriteStatusCache keeps st at path, readable by the shell and
// sneakers-osadmin (mode 0644): it holds what the status page shows,
// nothing secret.
func WriteStatusCache(path string, st *osadminv1.GetStatusResponse, saved time.Time) error {
	raw, err := protojson.Marshal(st)
	if err != nil {
		return err
	}
	b, err := json.Marshal(cacheFile{Saved: saved.UTC(), Status: raw})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { // #nosec G301 -- the shell's uid reads the cache
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil { // #nosec G306 -- status data, read by the shell and osadmin
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil { // #nosec G302 -- as above, past the umask
		return err
	}
	return os.Rename(tmp, path)
}
