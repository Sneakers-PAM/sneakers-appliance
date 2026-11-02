// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package boxsettings

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// defaultCollectorPort is the port of an endpoint that names none.
const defaultCollectorPort = "443"

// probeBound is how long a save waits for the collector's TLS handshake.
const probeBound = 10 * time.Second

// TelemetryCAFile is where the product's services find the collector's CA:
// the product mounts the CA setting there (build/product/sneakers
// values.yaml), and the OTLP exporters read it through
// OTEL_EXPORTER_OTLP_CERTIFICATE.
const TelemetryCAFile = "/etc/sneakers/otlp/ca.pem"

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
	// CA is the collector's CA, PEM. Set, it's what the collector's
	// certificate is checked against, in place of the system roots: the
	// OTLP exporters read a CA file that way.
	CA string `json:"ca,omitempty"`
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
	if t.CA != "" {
		if _, err := parseCA(t.CA, "collector", telemetryRefused); err != nil {
			return err
		}
	}
	return nil
}

// Probe shakes hands with the collector, checking its certificate unless
// SkipVerify says not to: against the CA when one is set, as the services'
// exporters will, else the system roots. Off, it asks nothing.
func (t Telemetry) Probe(ctx context.Context) error {
	if !t.Enabled {
		return nil
	}
	if err := t.Check(); err != nil {
		return err
	}
	u, err := url.Parse(t.Endpoint)
	if err != nil {
		return telemetryRefused("the collector endpoint %q isn't an https:// address", t.Endpoint)
	}
	port := u.Port()
	if port == "" {
		port = defaultCollectorPort
	}
	ctx, cancel := context.WithTimeout(ctx, probeBound)
	defer cancel()
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: t.SkipVerify, ServerName: u.Hostname()} // #nosec G402 -- skip-verify is the admin's choice, and the page warns
	if t.CA != "" && !t.SkipVerify {
		certs, err := parseCA(t.CA, "collector", telemetryRefused)
		if err != nil {
			return err
		}
		cfg.RootCAs = x509.NewCertPool()
		for _, c := range certs {
			cfg.RootCAs.AddCert(c)
		}
	}
	d := tls.Dialer{Config: cfg}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return codes.New(codes.TelemetryUnreachable, "the collector at %s can't be reached over TLS: %v", u.Host, err)
	}
	_ = c.Close()
	return nil
}

// Values are the settings by the names a product.yaml reads. Off, the
// services see no endpoint; with the collector unverified, no logs.
func (t Telemetry) Values() map[string]string {
	endpoint := ""
	if t.Enabled {
		endpoint = t.Endpoint
	}
	port := ""
	if u, err := url.Parse(t.Endpoint); t.Enabled && err == nil {
		if port = u.Port(); port == "" {
			port = defaultCollectorPort
		}
	}
	ca, caFile := "", ""
	if t.Enabled {
		ca = t.CA
	}
	if t.Enabled && t.CA != "" && !t.SkipVerify {
		caFile = TelemetryCAFile
	}
	return map[string]string{
		productspec.SettingTelemetryEndpoint:   endpoint,
		productspec.SettingTelemetryPort:       port,
		productspec.SettingTelemetrySkipVerify: strconv.FormatBool(t.SkipVerify),
		productspec.SettingTelemetryLogs:       strconv.FormatBool(t.Enabled && t.Logs && !t.SkipVerify),
		productspec.SettingTelemetryCA:         ca,
		productspec.SettingTelemetryCAFile:     caFile,
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
