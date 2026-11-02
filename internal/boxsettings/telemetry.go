// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package boxsettings

import (
	"net"
	"net/url"
	"strconv"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// Telemetry is where the product's services export traces, metrics and
// logs. Off stops the export and keeps the endpoint.
type Telemetry struct {
	Enabled  bool   `json:"enabled"`
	Endpoint string `json:"endpoint"`
	// SkipVerify skips the collector's CA and certificate checks. Logs
	// don't leave while it's on.
	SkipVerify bool `json:"skip_verify"`
	// Logs exports logs as well as traces and metrics.
	Logs bool `json:"logs"`
}

func telemetryRefused(format string, args ...any) error {
	return codes.New(codes.TelemetryInvalid, format, args...)
}

// Check refuses an endpoint that isn't https://<host>[:<port>]. A saved
// endpoint is held to that while off too, so switching on can't fail.
func (t Telemetry) Check() error {
	if t.Endpoint == "" {
		if t.Enabled {
			return telemetryRefused("telemetry needs a collector endpoint")
		}
		return nil
	}
	u, err := url.Parse(t.Endpoint)
	if err != nil || u.Scheme != "https" {
		return telemetryRefused("the collector endpoint %q isn't an https:// address", t.Endpoint)
	}
	if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return telemetryRefused("the collector endpoint %q has more than a host and a port", t.Endpoint)
	}
	host := u.Hostname()
	if len(host) > 253 || (!hostRE.MatchString(host) && net.ParseIP(host) == nil) {
		return telemetryRefused("the collector endpoint %q has no host name or address", t.Endpoint)
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return telemetryRefused("the collector port %q isn't 1 to 65535", p)
		}
	}
	return nil
}

// Values are the settings by the names a product.yaml reads. Off, the
// services see no endpoint; with the collector unverified, no logs.
func (t Telemetry) Values() map[string]string {
	endpoint := ""
	if t.Enabled {
		endpoint = t.Endpoint
	}
	return map[string]string{
		productspec.SettingTelemetryEndpoint:   endpoint,
		productspec.SettingTelemetrySkipVerify: strconv.FormatBool(t.SkipVerify),
		productspec.SettingTelemetryLogs:       strconv.FormatBool(t.Enabled && t.Logs && !t.SkipVerify),
	}
}

// Telemetry is the saved telemetry settings, or off.
func (s *Store) Telemetry() (Telemetry, error) {
	f, err := s.read()
	if err != nil {
		return Telemetry{}, err
	}
	if f.Telemetry == nil {
		return Telemetry{}, nil
	}
	return *f.Telemetry, nil
}

// SetTelemetry checks and saves the telemetry settings.
func (s *Store) SetTelemetry(t Telemetry) error {
	if err := t.Check(); err != nil {
		return err
	}
	f, err := s.read()
	if err != nil {
		return err
	}
	f.Telemetry = &t
	return s.write(f)
}
