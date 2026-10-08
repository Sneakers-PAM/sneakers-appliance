// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package audittest checks, in tests, that the OS audit log names things
// in words: every entry's target is something an admin reads (an admin's
// name, "*.example.org", "alice's browser session from 192.0.2.20"), never
// an id, which belongs in the entry's detail.
package audittest

import (
	"regexp"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

var idShapes = []*regexp.Regexp{
	// A UUID.
	regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
	// A hex id, such as a certificate's or a CSR's.
	regexp.MustCompile(`(?i)^[0-9a-f]{8,}$`),
	// A prefixed short id: R-7K2Q (a root shell), L-... (an SSH login),
	// E-... and the like.
	regexp.MustCompile(`^[A-Z]{1,2}-[0-9A-Za-z_-]{4,}$`),
	// A session id, web-..., ssh-... or elevated-....
	regexp.MustCompile(`^(web|ssh|elevated)-`),
	// A key fingerprint.
	regexp.MustCompile(`^SHA256:`),
	// An upload's id.
	regexp.MustCompile(`^(upload|up)-`),
}

// IDShaped reports whether target looks like an id rather than a name.
func IDShaped(target string) bool {
	for _, re := range idShapes {
		if re.MatchString(target) {
			return true
		}
	}
	return false
}

// CheckTargets fails t for every entry in l whose target is an id.
func CheckTargets(t testing.TB, l *osaudit.Log) {
	t.Helper()
	es, err := l.Entries()
	if err != nil {
		t.Errorf("audit entries: %v", err)
		return
	}
	for _, e := range es {
		if IDShaped(e.Target) {
			t.Errorf("audit %s names its target by id %q; name it in words and put the id in the detail", e.Action, e.Target)
		}
	}
}
