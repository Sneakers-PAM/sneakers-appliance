// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package release carries the keys a release must be signed with, stamped
// into the binary at build time.
//
// The pins are link-time variables, not configuration: whoever could edit
// a config file could then authorise their own image, so the anchor for what
// the kit and the box accept is fixed by whoever built them. Every pin is
// mandatory, and a build missing any of them refuses to start.
//
//	go build -ldflags "\
//	  -X github.com/Sneakers-PAM/sneakers-appliance/internal/release.Channel=lab \
//	  -X github.com/Sneakers-PAM/sneakers-appliance/internal/release.ReleaseKey=$(base64 -w0 cosign.pub) \
//	  -X github.com/Sneakers-PAM/sneakers-appliance/internal/release.DBCert=$(base64 -w0 db.crt) \
//	  -X github.com/Sneakers-PAM/sneakers-appliance/internal/release.PKCert=$(base64 -w0 PK.crt) \
//	  -X github.com/Sneakers-PAM/sneakers-appliance/internal/release.KEKCert=$(base64 -w0 KEK.crt) \
//	  -X github.com/Sneakers-PAM/sneakers-appliance/internal/release.FeedKey=$(base64 -w0 feed.pub) \
//	  -X github.com/Sneakers-PAM/sneakers-appliance/internal/release.Version=0.1.0"
package release

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// The stamped values: base64 (standard encoding) of each PEM file, and the
// channel. All are empty in a plain `go build`.
var (
	ReleaseKey string
	DBCert     string
	PKCert     string
	KEKCert    string
	Channel    string
	// Version is the kit or init version.
	Version = "0.0.0-dev"
	// Mirrors is the built-in list of update sources a lab build names
	// (comma-separated base URLs, walked in order), compiled into the
	// signed root. A production build's list is its release source.
	Mirrors string
	// FeedKey is the update feed's public key (base64 of the PEM), pinned in
	// a production build: the built-in update source is the feed, signed by
	// it. FeedKey2 is a second key for a rotation, and FeedKeyNotAfter
	// (RFC 3339) the time after which FeedKey no longer verifies the feed.
	// A lab build has no feed and needs none.
	FeedKey         string
	FeedKey2        string
	FeedKeyNotAfter string
)

// The channels a build may carry. A lab build is signed with a throwaway
// per-run key and is refused by a production build, and the reverse.
const (
	ChannelProduction = "production"
	ChannelLab        = "lab"
)

// Pins are the decoded stamped values.
type Pins struct {
	ReleaseKeyPEM []byte // cosign public key (PKIX)
	DBCertPEM     []byte
	PKCertPEM     []byte
	KEKCertPEM    []byte
	Channel       string
	// FeedKeyPEM, FeedKey2PEM and FeedKeyNotAfter are the update feed's
	// keys, mandatory in a production build.
	FeedKeyPEM      []byte
	FeedKey2PEM     []byte
	FeedKeyNotAfter time.Time
}

// Fingerprints are the lowercase hex SHA-256 of each pin's DER.
type Fingerprints struct {
	ReleaseKey, DB, PK, KEK, FeedKey string
}

// Load decodes the stamped pins. Any empty or undecodable pin, or a channel
// other than production or lab, is KIT_PIN_MISSING.
func Load() (Pins, error) {
	switch Channel {
	case ChannelProduction, ChannelLab:
	default:
		return Pins{}, codes.New(codes.KitPinMissing, "this build's channel is %q; it must be %q or %q", Channel, ChannelProduction, ChannelLab)
	}
	var p Pins
	p.Channel = Channel
	for _, f := range []struct {
		name, b64, pemType string
		dst                *[]byte
	}{
		{"release key", ReleaseKey, "PUBLIC KEY", &p.ReleaseKeyPEM},
		{"db certificate", DBCert, "CERTIFICATE", &p.DBCertPEM},
		{"PK certificate", PKCert, "CERTIFICATE", &p.PKCertPEM},
		{"KEK certificate", KEKCert, "CERTIFICATE", &p.KEKCertPEM},
	} {
		b, err := decode(f.b64, f.pemType)
		if err != nil {
			return Pins{}, codes.New(codes.KitPinMissing, "the %s pin: %v", f.name, err)
		}
		*f.dst = b
	}
	if err := loadFeedPins(&p); err != nil {
		return Pins{}, err
	}
	return p, nil
}

// loadFeedPins reads the update feed's keys: mandatory in a production build,
// optional in a lab one, and always a PKIX public key when given.
func loadFeedPins(p *Pins) error {
	if strings.TrimSpace(FeedKey) == "" {
		if p.Channel == ChannelProduction {
			return codes.New(codes.KitPinMissing, "the update feed key pin: %v", errEmpty)
		}
		if strings.TrimSpace(FeedKey2) != "" || strings.TrimSpace(FeedKeyNotAfter) != "" {
			return codes.New(codes.KitPinMissing, "the update feed key pin: a second key or an expiry without the key")
		}
		return nil
	}
	b, err := decode(FeedKey, "PUBLIC KEY")
	if err != nil {
		return codes.New(codes.KitPinMissing, "the update feed key pin: %v", err)
	}
	p.FeedKeyPEM = b
	if strings.TrimSpace(FeedKey2) != "" {
		if b, err = decode(FeedKey2, "PUBLIC KEY"); err != nil {
			return codes.New(codes.KitPinMissing, "the second update feed key pin: %v", err)
		}
		p.FeedKey2PEM = b
	}
	if s := strings.TrimSpace(FeedKeyNotAfter); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return codes.New(codes.KitPinMissing, "the update feed key's expiry %q isn't an RFC 3339 time", s)
		}
		p.FeedKeyNotAfter = t
	}
	return nil
}

func decode(b64, pemType string) ([]byte, error) {
	b64 = strings.TrimSpace(b64)
	if b64 == "" {
		return nil, errEmpty
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	der, err := firstDER(raw, pemType)
	if err != nil {
		return nil, err
	}
	switch pemType {
	case "CERTIFICATE":
		if _, err := x509.ParseCertificate(der); err != nil {
			return nil, err
		}
	case "PUBLIC KEY":
		if _, err := x509.ParsePKIXPublicKey(der); err != nil {
			return nil, err
		}
	}
	return raw, nil
}

type pinError string

func (e pinError) Error() string { return string(e) }

const (
	errEmpty  = pinError("it is empty")
	errNotPEM = pinError("it holds no PEM block of the expected type")
)

func firstDER(pemBytes []byte, pemType string) ([]byte, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil || blk.Type != pemType {
		return nil, errNotPEM
	}
	return blk.Bytes, nil
}

// Fingerprint returns the lowercase hex SHA-256 of the first PEM block's DER,
// or "" when b holds none.
func Fingerprint(b []byte) string {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return ""
	}
	sum := sha256.Sum256(blk.Bytes)
	return hex.EncodeToString(sum[:])
}

// Fingerprints returns each pin's fingerprint.
func (p Pins) Fingerprints() Fingerprints {
	return Fingerprints{
		ReleaseKey: Fingerprint(p.ReleaseKeyPEM),
		DB:         Fingerprint(p.DBCertPEM),
		PK:         Fingerprint(p.PKCertPEM),
		KEK:        Fingerprint(p.KEKCertPEM),
		FeedKey:    Fingerprint(p.FeedKeyPEM),
	}
}

// SetForTest stamps the pins from PEM text (encoding them as a build would)
// and returns a function that restores the previous values.
func SetForTest(channel, releaseKeyPEM, dbPEM, pkPEM, kekPEM string) (restore func()) {
	prev := [5]string{Channel, ReleaseKey, DBCert, PKCert, KEKCert}
	enc := func(s string) string {
		if s == "" {
			return ""
		}
		return base64.StdEncoding.EncodeToString([]byte(s))
	}
	Channel, ReleaseKey, DBCert, PKCert, KEKCert = channel, enc(releaseKeyPEM), enc(dbPEM), enc(pkPEM), enc(kekPEM)
	return func() { Channel, ReleaseKey, DBCert, PKCert, KEKCert = prev[0], prev[1], prev[2], prev[3], prev[4] }
}

// SetFeedForTest stamps the update feed's pins from PEM text and an RFC 3339
// expiry and returns a function that restores the previous values.
func SetFeedForTest(feedPEM, feed2PEM, notAfter string) (restore func()) {
	prev := [3]string{FeedKey, FeedKey2, FeedKeyNotAfter}
	enc := func(s string) string {
		if s == "" {
			return ""
		}
		return base64.StdEncoding.EncodeToString([]byte(s))
	}
	FeedKey, FeedKey2, FeedKeyNotAfter = enc(feedPEM), enc(feed2PEM), notAfter
	return func() { FeedKey, FeedKey2, FeedKeyNotAfter = prev[0], prev[1], prev[2] }
}
