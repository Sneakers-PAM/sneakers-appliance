// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package acmebox is cert-manager on the box, as internal/certstore sees it
// (certstore.ACMEDriver): the stack k0s applies from
// /var/lib/k0s/manifests/box-acme, and what cert-manager has made, read
// through the appliance's read-only service account.
package acmebox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/acme"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/certstore"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/kubeapi"
)

// Reader is the API server, read only.
type Reader interface {
	Secret(ctx context.Context, namespace, name string) (map[string][]byte, error)
	Object(ctx context.Context, path string) ([]byte, error)
}

// Box is the driver.
type Box struct {
	// Slot is the product's current slot; it has bundle.json once a product
	// is installed, and manifests/cert-manager when the bundle runs it.
	Slot string
	// Manifests is k0s's manifests directory (/var/lib/k0s/manifests).
	Manifests string
	Kube      Reader
}

var _ certstore.ACMEDriver = (*Box)(nil)

// Available says whether the installed bundle runs cert-manager.
func (b *Box) Available() (bool, string) {
	if _, err := os.Stat(filepath.Join(b.Slot, "bundle.json")); err != nil {
		return false, "ACME is available when the product is installed: cert-manager comes with its bundle."
	}
	if st, err := os.Stat(filepath.Join(b.Slot, "manifests", "cert-manager")); err != nil || !st.IsDir() {
		return false, "The installed product bundle doesn't carry cert-manager; update to one that does to use ACME."
	}
	return true, ""
}

func (b *Box) dir() string { return filepath.Join(b.Manifests, acme.Stack) }

// Apply writes the stack, replacing the one before. The file is root only:
// it carries the DNS provider's token.
func (b *Box) Apply(_ context.Context, manifests []byte) error {
	if err := os.MkdirAll(b.dir(), 0o700); err != nil {
		return fmt.Errorf("acmebox: %w", err)
	}
	p := filepath.Join(b.dir(), acme.Stack+".yaml")
	tmp, err := os.CreateTemp(b.dir(), ".stack-*")
	if err != nil {
		return fmt.Errorf("acmebox: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("acmebox: %w", err)
	}
	if _, err := tmp.Write(manifests); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("acmebox: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("acmebox: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("acmebox: %w", err)
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		return fmt.Errorf("acmebox: %w", err)
	}
	return nil
}

// Remove takes the stack away, so k0s removes what it applied.
func (b *Box) Remove(context.Context) error {
	if err := os.RemoveAll(b.dir()); err != nil {
		return fmt.Errorf("acmebox: %w", err)
	}
	return nil
}

// certificate is the part of cert-manager's Certificate this reads.
type certificate struct {
	Status struct {
		LastFailureTime *time.Time `json:"lastFailureTime"`
		Conditions      []struct {
			Type    string `json:"type"`
			Status  string `json:"status"`
			Message string `json:"message"`
		} `json:"conditions"`
	} `json:"status"`
}

// Status reads the issued pair and the Certificate's conditions. Neither
// existing yet is an empty status, not an error: cert-manager hasn't got
// to it.
func (b *Box) Status(ctx context.Context) (certstore.ACMEStatus, error) {
	var out certstore.ACMEStatus
	sec, err := b.Kube.Secret(ctx, acme.Namespace, acme.SecretName)
	switch {
	case err == nil:
		out.CertPEM, out.KeyPEM = sec["tls.crt"], sec["tls.key"]
	case !errors.Is(err, kubeapi.ErrNotFound):
		return out, err
	}
	raw, err := b.Kube.Object(ctx, "/apis/cert-manager.io/v1/namespaces/"+acme.Namespace+"/certificates/"+acme.CertName) // scrub:allow=fqdn -- a Kubernetes API group
	switch {
	case err == nil:
	case errors.Is(err, kubeapi.ErrNotFound):
		return out, nil
	default:
		return out, err
	}
	var c certificate
	if err := json.Unmarshal(raw, &c); err != nil {
		return out, fmt.Errorf("acmebox: the Certificate doesn't parse: %w", err)
	}
	var issuing string
	for _, cond := range c.Status.Conditions {
		switch cond.Type {
		case "Ready":
			out.Ready = cond.Status == "True"
		case "Issuing":
			if cond.Status == "True" {
				issuing = cond.Message
			}
		}
	}
	// cert-manager keeps the old pair in the Secret while a renewal fails,
	// and says so in the Issuing condition: "has failed to complete and
	// will be retried". A failure time with nothing issuing isn't current.
	if c.Status.LastFailureTime != nil && issuing != "" && containsFailure(issuing) {
		out.Failure = issuing
	}
	return out, nil
}

func containsFailure(msg string) bool {
	msg = strings.ToLower(msg)
	for _, w := range []string{"failed", "errored", "rejected", "denied"} {
		if strings.Contains(msg, w) {
			return true
		}
	}
	return false
}
