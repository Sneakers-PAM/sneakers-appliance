// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package boxsettings_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxsettings"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// otherCA is a CA that signed nothing the tests serve.
func otherCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "another CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// The save's handshake trusts the collector's CA once it's set, and only
// that CA: the services' exporters read it in place of the system roots.
func TestTheCollectorCAIsWhatTheProbeTrusts(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer ts.Close()
	ctx := context.Background()
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}))
	if err := (boxsettings.Telemetry{Enabled: true, Endpoint: ts.URL, CA: caPEM}).Probe(ctx); err != nil {
		t.Fatalf("the collector's CA: %v", err)
	}
	if err := (boxsettings.Telemetry{Enabled: true, Endpoint: ts.URL, CA: otherCA(t)}).Probe(ctx); !codes.Is(err, codes.TelemetryUnreachable) {
		t.Fatalf("another CA: %v", err)
	}
}

func TestABadCollectorCAIsRefused(t *testing.T) {
	for name, ca := range map[string]string{
		"not PEM":        "not a certificate",
		"no certificate": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1, 2, 3}})),
		"a broken PEM":   "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
	} {
		tl := boxsettings.Telemetry{Enabled: true, Endpoint: "https://collector.example.com:4317", CA: ca}
		if err := tl.Check(); !codes.Is(err, codes.TelemetryInvalid) {
			t.Errorf("%s: %v", name, err)
		}
		if err := (&boxsettings.Store{Dir: t.TempDir()}).SetTelemetry(tl); err == nil {
			t.Errorf("%s: saved", name)
		}
	}
}

// The CA is kept with the other telemetry settings, and the services get
// it while export is on and verified: its PEM, and the file the exporters
// read it from.
func TestTheCollectorCAReachesTheServices(t *testing.T) {
	ca := otherCA(t)
	st := boxsettings.Store{Dir: t.TempDir()}
	want := boxsettings.Telemetry{Enabled: true, Endpoint: "https://collector.example.com:4317", Logs: true, CA: ca}
	if err := st.SetTelemetry(want); err != nil {
		t.Fatal(err)
	}
	if got, err := st.Telemetry(); err != nil || got != want {
		t.Fatalf("saved %+v, read %+v, %v", want, got, err)
	}
	v := want.Values()
	if v[productspec.SettingTelemetryCA] != ca || v[productspec.SettingTelemetryCAFile] != boxsettings.TelemetryCAFile || v[productspec.SettingTelemetryLogs] != "true" {
		t.Fatalf("on with a CA: %v", v)
	}
	for name, tl := range map[string]boxsettings.Telemetry{
		"off":         {Endpoint: want.Endpoint, CA: ca},
		"no CA":       {Enabled: true, Endpoint: want.Endpoint},
		"skip-verify": {Enabled: true, Endpoint: want.Endpoint, CA: ca, SkipVerify: true},
	} {
		v := tl.Values()
		if v[productspec.SettingTelemetryCAFile] != "" {
			t.Errorf("%s: the exporters read a CA file: %v", name, v)
		}
		if _, ok := v[productspec.SettingTelemetryCA]; !ok {
			t.Errorf("%s: no CA value at all, so the file mount has no key: %v", name, v)
		}
	}
}
