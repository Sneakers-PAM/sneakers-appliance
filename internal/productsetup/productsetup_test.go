// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productsetup_test

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productsetup"
)

// The box makes one product setup token, keeps it until the product's
// first admin exists, then removes it for good.
func TestOneTokenUntilItsConsumed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "product-setup")
	s := productsetup.New(dir)
	if _, ok := s.Token(); ok {
		t.Fatal("a token before Ensure")
	}
	if err := s.Ensure(); err != nil {
		t.Fatal(err)
	}
	tok, ok := s.Token()
	if !ok || !regexp.MustCompile(`^stp_[a-z2-7]{32}$`).MatchString(tok) {
		t.Fatalf("token %q", tok)
	}
	if fi, err := os.Stat(filepath.Join(dir, productsetup.TokenFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("token file %v %v", fi, err)
	}
	if err := s.Ensure(); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.Token(); again != tok {
		t.Fatal("Ensure made a second token")
	}
	if s.Consumed() {
		t.Fatal("consumed before Consume")
	}
	if err := s.Consume(); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Token(); ok || !s.Consumed() {
		t.Fatal("the token outlived Consume")
	}
	if _, err := os.Stat(filepath.Join(dir, productsetup.TokenFile)); !os.IsNotExist(err) {
		t.Fatal("the token file is still there")
	}
	if err := s.Ensure(); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Token(); ok {
		t.Fatal("Ensure made a token after it was consumed")
	}
}
