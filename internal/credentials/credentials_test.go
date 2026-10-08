// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package credentials_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/credentials"
)

var pepper = bytes.Repeat([]byte{7}, 32)

func TestAPasswordHashIsArgon2idKeyedWithThePepper(t *testing.T) {
	h, err := credentials.HashPassword(pepper, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("hash %q", h)
	}
	if !credentials.VerifyPassword(pepper, h, "correct horse battery") {
		t.Fatal("the right password doesn't verify")
	}
	if credentials.VerifyPassword(pepper, h, "correct horse batterY") {
		t.Fatal("a wrong password verifies")
	}
	other := bytes.Repeat([]byte{8}, 32)
	if credentials.VerifyPassword(other, h, "correct horse battery") {
		t.Fatal("the hash verifies without this box's pepper")
	}
	h2, _ := credentials.HashPassword(pepper, "correct horse battery")
	if h2 == h {
		t.Fatal("two hashes of one password share a salt")
	}
	if credentials.VerifyPassword(pepper, "not a hash", "x") {
		t.Fatal("a broken hash verifies")
	}
}

func TestThePasswordRules(t *testing.T) {
	ok := []string{"correct horse battery", "violet tractor lamp", "日本語のパスワードです長い"}
	for _, p := range ok {
		if err := credentials.CheckPassword(p, "alice"); err != nil {
			t.Errorf("%q refused: %v", p, err)
		}
	}
	short := credentials.CheckPassword("short-pass1", "alice")
	if !codes.Is(short, codes.AccessPassword) || !strings.Contains(short.Error(), "12") {
		t.Fatalf("a short password: %v", short)
	}
	if err := credentials.CheckPassword("alicealicealice", "alicealicealice"); !codes.Is(err, codes.AccessPassword) {
		t.Fatalf("the name as the password: %v", err)
	}
	if err := credentials.CheckPassword("password1234", "alice"); !codes.Is(err, codes.AccessPassword) || !credentials.Breached("password1234") {
		t.Fatalf("a breached password: %v", err)
	}
	if err := credentials.CheckPassword("PASSWORD1234", "alice"); !codes.Is(err, codes.AccessPassword) {
		t.Fatalf("a breached password in capitals: %v", err)
	}
	if credentials.BreachedCount() < 40000 {
		t.Fatalf("the breached list has only %d entries", credentials.BreachedCount())
	}
}

func TestTOTPMatchesRFC6238(t *testing.T) {
	// RFC 6238 Appendix B, SHA-1, with 6 digits.
	secret := []byte("12345678901234567890")
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"} {
		if got := credentials.TOTP(secret, time.Unix(unix, 0)); got != want {
			t.Errorf("TOTP at %d = %s, want %s", unix, got, want)
		}
	}
}

func TestTOTPVerifyTakesOneStepEitherSideAndNeverTheSameStepTwice(t *testing.T) {
	secret, err := credentials.NewTOTPSecret()
	if err != nil || len(secret) != 20 {
		t.Fatalf("secret: %v", err)
	}
	now := time.Unix(1_800_000_000, 0)
	code := credentials.TOTP(secret, now.Add(-30*time.Second))
	step, ok := credentials.VerifyTOTP(secret, code, now, 0)
	if !ok {
		t.Fatal("the previous step's code was refused")
	}
	if _, ok := credentials.VerifyTOTP(secret, code, now, step); ok {
		t.Fatal("a code was accepted twice")
	}
	if _, ok := credentials.VerifyTOTP(secret, credentials.TOTP(secret, now.Add(-90*time.Second)), now, 0); ok {
		t.Fatal("a code three steps old was accepted")
	}
	if _, ok := credentials.VerifyTOTP(secret, "12345", now, 0); ok {
		t.Fatal("a 5-digit code was accepted")
	}
	if _, ok := credentials.VerifyTOTP(secret, " "+credentials.TOTP(secret, now)+" ", now, 0); !ok {
		t.Fatal("spaces around a right code were refused")
	}
}

func TestTOTPSecretsAreSealedUnderThePepper(t *testing.T) {
	secret, _ := credentials.NewTOTPSecret()
	sealed, err := credentials.SealTOTP(pepper, "alice", secret)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, credentials.Base32(secret)) {
		t.Fatal("the sealed form holds the secret")
	}
	back, err := credentials.OpenTOTP(pepper, "alice", sealed)
	if err != nil || !bytes.Equal(back, secret) {
		t.Fatalf("open: %v", err)
	}
	if _, err := credentials.OpenTOTP(pepper, "bob", sealed); err == nil {
		t.Fatal("alice's secret opened as bob's")
	}
	if _, err := credentials.OpenTOTP(bytes.Repeat([]byte{9}, 32), "alice", sealed); err == nil {
		t.Fatal("the secret opened without this box's pepper")
	}
}

func TestTheOtpauthURI(t *testing.T) {
	uri := credentials.URI([]byte("12345678901234567890"), "sneakers.example.org", "alice")
	want := "otpauth://totp/sneakers.example.org:alice?algorithm=SHA1&digits=6&issuer=sneakers.example.org&period=30&secret=" + credentials.Base32([]byte("12345678901234567890"))
	if uri != want {
		t.Fatalf("uri\n%s\nwant\n%s", uri, want)
	}
}
