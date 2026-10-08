// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"
	"net/netip"
	"strings"
	"time"
)

// SetupState is how far the :8443 setup has got.
type SetupState int

// The setup states.
const (
	SetupNotStarted SetupState = iota
	SetupInProgress
	SetupDone
)

// RecoverCode is a live Recover access code: it opens :8443/recover once.
type RecoverCode struct {
	Code         string
	Expires      time.Time
	AttemptsLeft int
	URL          string
	// InUse is set once a browser redeemed it, from Source.
	InUse  bool
	Source string
}

// ConsoleInfo is what the access backend tells the console: the one-time
// setup code or setup's progress, where :8443 is and the certificate to
// check, and a live Recover access code.
type ConsoleInfo struct {
	State SetupState
	// SetupCode is XXXX-XXXX-XXXX-XXXX (Crockford base32) while setup
	// hasn't started.
	SetupCode    string
	CodeExpires  time.Time
	AttemptsLeft int
	// URL is :8443 on the first management address; URLs on each.
	URL  string
	URLs []string
	// FQDN is the box's name once a hostname or domain is set: the page is
	// also https://<FQDN>:8443.
	FQDN string
	// CodeLocked is set once wrong tries locked the code out; none works
	// until the console asks for a new one.
	CodeLocked bool
	// CertFingerprint is :8443's certificate's SHA-256 in hex.
	CertFingerprint string
	// SetupSource and SetupStarted are the browser that redeemed the code.
	SetupSource  string
	SetupStarted time.Time
	// SetupStep is the browser's step (1 to SetupSteps), named StepName.
	SetupStep, SetupSteps int
	StepName              string
	// FirstAdmin is set once the first admin exists; SSHOn once SSH may
	// run.
	FirstAdmin string
	SSHOn      bool
	Recover    *RecoverCode
}

// ConsoleAccess is the access backend as the console uses it.
type ConsoleAccess interface {
	Read(ctx context.Context) (ConsoleInfo, error)
	// Changed is signalled when the info changes (a new code, a browser
	// starting setup, a step done), so the screen redraws at once.
	Changed() <-chan struct{}
	// Watch follows the changes until ctx ends.
	Watch(ctx context.Context)
	// ResetSetupCode stops a browser setup that hasn't made the first
	// admin yet, and makes a new code.
	ResetSetupCode(ctx context.Context) error
	BeginRecoverAccess(ctx context.Context) (RecoverCode, error)
	CancelRecoverAccess(ctx context.Context) error
}

// URLHosts turns addresses (with or without a prefix) into URL hosts:
// link-local ones left out, IPv6 in brackets.
func URLHosts(addrs []string) []string {
	var out []string
	for _, a := range addrs {
		ip, err := netip.ParseAddr(a)
		if err != nil {
			p, perr := netip.ParsePrefix(a)
			if perr != nil {
				continue
			}
			ip = p.Addr()
		}
		if ip.IsLinkLocalUnicast() {
			continue
		}
		if ip.Is6() {
			out = append(out, "["+ip.String()+"]")
			continue
		}
		out = append(out, ip.String())
	}
	return out
}

// Hosts is URLHosts without the brackets: the addresses to show.
func Hosts(addrs []string) []string {
	var out []string
	for _, h := range URLHosts(addrs) {
		out = append(out, strings.Trim(h, "[]"))
	}
	return out
}
