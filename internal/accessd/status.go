// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/encoding/protojson"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
)

// StatusFile is where accessd keeps the last status on the box.
const StatusFile = "/run/sneakers/access/status.json"

// StatusCache is the last status accessd computed and when.
type StatusCache struct {
	Saved  time.Time
	Status *osadminv1.GetStatusResponse
}

type cacheFile struct {
	Saved  time.Time       `json:"saved"`
	Status json.RawMessage `json:"status"`
}

// ReadStatusCache reads the status accessd last kept.
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

// saveStatus keeps st for the shell and sneakers-osadmin, readable by
// both (mode 0644): it holds what the status page shows, nothing secret.
func (s *Server) saveStatus(st *osadminv1.GetStatusResponse) {
	if s.o.StatusFile == "" || st == nil {
		return
	}
	raw, err := protojson.Marshal(st)
	if err == nil {
		var b []byte
		b, err = json.Marshal(cacheFile{Saved: time.Now().UTC(), Status: raw})
		if err == nil {
			err = writeFile(s.o.StatusFile, b)
		}
	}
	if err != nil {
		s.o.Logger.Warn("accessd: status cache not written", log.F("error", err.Error()))
	}
}

func writeFile(p string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { // #nosec G301 -- the shell's uid reads the cache
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil { // #nosec G306 -- status data, read by the shell and osadmin
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil { // #nosec G302 -- as above, past the umask
		return err
	}
	return os.Rename(tmp, p)
}

// RefreshStatus computes the status as the console and keeps it, so the
// cache is fresh even when nobody asks.
func (s *Server) RefreshStatus(ctx context.Context) {
	st, err := runAs(ctx, s, osadmin.Local{Source: "accessd"}, osadminv1connect.StatusServiceGetStatusProcedure, s.h.Status.GetStatus, &osadminv1.GetStatusRequest{})
	if err != nil {
		s.o.Logger.Warn("accessd: status refresh failed", log.F("error", err.Error()))
		return
	}
	s.saveStatus(st)
}
