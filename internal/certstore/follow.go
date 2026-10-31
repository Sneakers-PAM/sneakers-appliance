// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package certstore

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
)

// OwnReason is why the box's own certificate has to go; empty when it
// stays.
type OwnReason string

// The reasons.
const (
	OwnHostName  OwnReason = "hostname"
	OwnAddresses OwnReason = "addresses"
	OwnExpiring  OwnReason = "expiring"
	// OwnEdgeBehind isn't a new certificate: 443 hadn't caught up with the
	// one :8443 already serves.
	OwnEdgeBehind OwnReason = "edge-behind"
)

// previousItem is the sealed key of the box's last certificate.
const previousItem = "tls-" + selfSignedID + "-previous"

// OwnNeed says whether the box's own certificate has to change for the
// box's names now. Names identify those names, so a caller can tell a set
// that holds still from one that's still moving.
type OwnNeed struct {
	Reason OwnReason
	Names  string
}

// OwnChange is a change to the box's own certificate: one to audit, and to
// tell the admin about, since the fingerprint they checked is gone. New is
// empty when nothing changed.
type OwnChange struct {
	At       time.Time `json:"at"`
	Old      string    `json:"old"`
	New      string    `json:"new"`
	Reason   OwnReason `json:"reason"`
	Restored bool      `json:"restored,omitempty"`
	// Names are what the certificate had to cover.
	Names []string `json:"names,omitempty"`
	// Endpoints are the endpoints that serve it from now on.
	Endpoints []string `json:"endpoints,omitempty"`
}

// WhyReplace says why leaf can't stay the box's own certificate for
// hostname and addrs at now; empty when it can. A certificate that names
// more addresses than addrs stays: after a boot they come back one at a
// time, and a fingerprint an admin checked must only change for a reason.
func WhyReplace(leaf *x509.Certificate, hostname string, addrs []string, now time.Time) OwnReason {
	if first(leaf.DNSNames) != hostname {
		return OwnHostName
	}
	have := make([]string, 0, len(leaf.IPAddresses))
	for _, ip := range leaf.IPAddresses {
		have = append(have, ip.String())
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && !slices.Contains(have, ip.String()) {
			return OwnAddresses
		}
	}
	if !now.Add(RenewBefore).Before(leaf.NotAfter) {
		return OwnExpiring
	}
	return ""
}

func first(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

// ownActive reports whether :8443 serves the box's own certificate, as far
// as the store and the files say. The caller holds s.mu.
func (s *Store) ownActive() bool {
	return s.assignments()[EndpointAdmin].Source == EndpointSelfSigned && AssignedID(s.o.AdminDir) == ""
}

// OwnNeed looks at the box's own certificate against the box's names. It
// changes nothing. A box with no address, an assigned certificate, or no
// certificate yet (sneakers-osadmin makes the first) needs nothing.
func (s *Store) OwnNeed(ctx context.Context) (OwnNeed, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.checking || !s.ownActive() {
		return OwnNeed{}, nil
	}
	host, addrs, err := s.names(ctx)
	if err != nil {
		return OwnNeed{}, err
	}
	if len(addrs) == 0 {
		return OwnNeed{}, nil
	}
	leaf, err := readAdminLeaf(s.o.AdminDir)
	if err != nil {
		return OwnNeed{}, nil //nolint:nilerr // osadmin makes one when nothing loads
	}
	return OwnNeed{Reason: WhyReplace(leaf, host, addrs, s.o.Now()), Names: strings.Join(sortedNames(boxNames(host, addrs)), ",")}, nil
}

// FollowOwn brings the box's own certificate up to the box's names and
// hands it to the edges that serve a copy. The caller has already decided
// the names are final (osadmin.Server.FollowCerts): they are read again
// here, so a change undone in between finds nothing to do.
//
// The certificate it replaces is kept, with its key sealed: when a later
// change makes the box what it was, that one comes back rather than
// another new one. If the key can't be sealed the certificate stays and the
// error says why, since replacing it would lose that fingerprint for good.
//
// An edge that couldn't be told is reported with the change and tried
// again on the next look.
func (s *Store) FollowOwn(ctx context.Context) (OwnChange, error) {
	defer s.change()()
	if !s.ownActive() {
		return OwnChange{}, nil
	}
	host, addrs, err := s.names(ctx)
	if err != nil {
		return OwnChange{}, err
	}
	if len(addrs) == 0 {
		return OwnChange{}, nil
	}
	crt, key, err := readAdminFiles(s.o.AdminDir)
	if err != nil {
		return OwnChange{}, nil //nolint:nilerr // osadmin makes one when nothing loads
	}
	certs, err := parseCerts("own", string(crt))
	if err != nil || len(certs) == 0 {
		return OwnChange{}, nil //nolint:nilerr // as above
	}
	var out OwnChange
	if why := WhyReplace(certs[0], host, addrs, s.o.Now()); why != "" {
		if out, crt, key, err = s.replaceOwn(why, certs[0], crt, key, host, addrs); err != nil {
			return OwnChange{}, err
		}
	}
	return s.followEdges(out, crt, key)
}

// replaceOwn writes the certificate that follows crt and key, the earlier
// one when it fits, else a new one, and returns the change and the pair now
// served.
func (s *Store) replaceOwn(why OwnReason, leaf *x509.Certificate, crt, key []byte, host string, addrs []string) (OwnChange, []byte, []byte, error) {
	now := s.o.Now()
	nextCrt, nextKey, err := s.savedPrevious(host, addrs)
	if err != nil {
		return OwnChange{}, nil, nil, err
	}
	restored := nextCrt != nil
	if !restored {
		if nextCrt, nextKey, err = NewSelfSigned(host, addrs, now); err != nil {
			return OwnChange{}, nil, nil, err
		}
	}
	// The outgoing pair is safe before it's overwritten, so a stop in
	// between loses nothing.
	if err := s.o.Sealer.Seal(previousItem, key); err != nil {
		return OwnChange{}, nil, nil, fmt.Errorf("tls: seal: %w", err)
	}
	s.st.Previous = &storedCert{ID: selfSignedID + "-previous", Source: SourceSelfSigned, PEM: string(crt), KeyItem: previousItem, Added: now}
	if err := s.save(); err != nil {
		return OwnChange{}, nil, nil, err
	}
	if err := s.writeAdmin(nextCrt, nextKey, ""); err != nil {
		return OwnChange{}, nil, nil, err
	}
	change := OwnChange{At: now, Old: Fingerprint(leaf.Raw), New: fingerprintPEM(nextCrt), Reason: why, Restored: restored,
		Names: boxNames(host, addrs), Endpoints: []string{EndpointAdmin}}
	s.st.Last = &change
	if err := s.captureSelfSigned(); err != nil {
		s.o.Logger.Warn("tls: the new certificate isn't recorded yet", log.F("error", err.Error()))
	}
	if err := s.save(); err != nil {
		s.o.Logger.Warn("tls: the change to the box's certificate isn't saved", log.F("error", err.Error()))
	}
	s.fallbackBehind = true
	s.o.Logger.Info("tls: the box's own certificate changed", log.F("old", change.Old), log.F("new", change.New), log.F("reason", string(why)), log.F("restored", restored))
	return change, nextCrt, nextKey, nil
}

// savedPrevious is the certificate the box had before, with its key, when
// it's still good for the box's names.
func (s *Store) savedPrevious(host string, addrs []string) ([]byte, []byte, error) {
	if s.st.Previous == nil {
		return nil, nil, nil
	}
	certs, err := parseCerts("store", s.st.Previous.PEM)
	if err != nil || len(certs) == 0 {
		return nil, nil, nil //nolint:nilerr // a damaged record just isn't put back
	}
	if WhyReplace(certs[0], host, addrs, s.o.Now()) != "" {
		return nil, nil, nil
	}
	key, ok, err := s.o.Sealer.Unseal(s.st.Previous.KeyItem)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: unseal: %w", err)
	}
	if !ok || len(key) == 0 {
		return nil, nil, nil
	}
	return []byte(s.st.Previous.PEM), key, nil
}

// followEdges gives 443 and edgefall the pair :8443 serves, as they both
// keep a copy. It adds what it did to change; each is safe to run on every
// look and does nothing when the copy is current.
func (s *Store) followEdges(change OwnChange, crt, key []byte) (OwnChange, error) {
	var failed error
	if s.o.Product != nil && s.o.Product.Installed() {
		old, moved, err := s.o.Product.Follow(crt, key)
		switch {
		case err != nil:
			s.o.Logger.Warn("tls: the product's edge didn't take the box's certificate; trying again on the next look", log.F("error", err.Error()))
			failed = fmt.Errorf("tls: the edge's certificate can't be written: %w", err)
		case moved && change.New != "":
			change.Endpoints = append(change.Endpoints, EndpointProduct)
		case moved:
			s.o.Logger.Info("tls: the product's edge caught up with the box's certificate", log.F("new", fingerprintPEM(crt)))
			change = OwnChange{At: s.o.Now(), Old: fingerprintPEM(old), New: fingerprintPEM(crt), Reason: OwnEdgeBehind, Endpoints: []string{EndpointProduct}}
		}
	}
	if s.fallbackBehind && s.o.Fallback != nil {
		if err := s.o.Fallback(); err != nil {
			s.o.Logger.Warn("tls: edgefall didn't take the box's certificate; trying again on the next look", log.F("error", err.Error()))
			if failed == nil {
				failed = fmt.Errorf("tls: edgefall's certificate can't be written: %w", err)
			}
		} else {
			s.fallbackBehind = false
		}
	}
	return change, failed
}

// LastOwnChange is the last change to the box's own certificate, kept
// across restarts.
func (s *Store) LastOwnChange() (OwnChange, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Last == nil {
		return OwnChange{}, false
	}
	return *s.st.Last, true
}
