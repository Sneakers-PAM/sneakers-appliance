// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package supportbundle

import (
	"regexp"
	"strings"
	"testing"
)

// The planted values are invented; none of them is a key anywhere.
const (
	plantPassword = "pl4nted-" + "hunter2"
	plantToken    = "pl4ntedT0kenValue99"
	plantJWT      = "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiJwbGFudGVkIn0" + "." + "c2lnbmF0dXJlLXBsYW50ZWQ"
	plantAge      = "AGE-SECRET-KEY-1QYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGP"
	plantSnk      = "snk_pl4ntedM4chineT0ken"
	plantBasic    = "dXNlcjpwbDRudGVk"
	plantKnown    = "9f3a7c1e5b2d4860a1c3e5f7091b3d5f"
	plantPEMBody  = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"
)

// pemLine builds a key's BEGIN or END line, so the source holds nothing a
// secret scanner takes for a key.
func pemLine(edge, kind string) string {
	return "-----" + edge + " " + kind + "PRIVATE " + "KEY-----"
}

func redactAll(t *testing.T, r *Redactor, text string) string {
	t.Helper()
	var out []string
	for line := range strings.SplitSeq(text, "\n") {
		if l, ok := r.Line(line); ok {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// Each case names the section type a value turns up in; a value may be in
// a log, a kubectl table, a describe, a JSON file or a status.
func TestRedactionRemovesEverySecretShape(t *testing.T) {
	cases := map[string]struct{ in, gone string }{
		"pod log: logfmt password":    {"level=info msg=connect password=" + plantPassword + " host=db", plantPassword},
		"pod log: bare token":         {"token=" + plantToken + " ok", plantToken},
		"pod log: secret key":         {"client_secret=" + plantToken, plantToken},
		"pod log: quoted value":       {`password="` + plantPassword + ` with spaces" next=1`, "with spaces"},
		"pod log: bearer header":      {"GET /x Authorization: Bearer " + plantToken, plantToken},
		"pod log: lower bearer":       {"sent bearer " + plantToken + " upstream", plantToken},
		"pod log: basic header":       {"Authorization: Basic " + plantBasic, plantBasic},
		"pod log: bare basic":         {"proxy sent Basic " + plantBasic + " upstream", plantBasic},
		"pod log: cookie":             {"Cookie: session=" + plantToken + "; theme=dark", plantToken},
		"pod log: set-cookie":         {"Set-Cookie: sid=" + plantToken + "; HttpOnly", plantToken},
		"pod log: api key header":     {"X-Api-Key: " + plantToken, plantToken},
		"pod log: snk token":          {"called with " + plantSnk + " today", plantSnk},
		"pod log: jwt":                {"verified " + plantJWT + " for alice", plantJWT},
		"pod log: jwt two parts":      {"cut eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwbGFudGVkIn0", "eyJzdWIiOiJwbGFudGVkIn0"},
		"pod log: github token":       {"fetched with ghp_pl4ntedGithubT0ken123", "ghp_pl4ntedGithubT0ken123"},
		"url: password":               {"dial postgres://sneakers:" + plantPassword + "@db:5432/x", plantPassword},
		"url: empty user":             {"dial redis://:" + plantPassword + "@cache:6379/0", plantPassword},
		"url: slash in password":      {"dial postgres://u:ab/" + plantPassword + "@db:5432/x", plantPassword},
		"json: secret field":          {`{"level":"info","password":"` + plantPassword + `","ok":true}`, plantPassword},
		"json: nested token":          {`{"auth":{"access_token":"` + plantToken + `"}}`, plantToken},
		"json: escaped in a string":   {`{"msg":"body {\"password\":\"` + plantPassword + `\"}"}`, plantPassword},
		"yaml: dump":                  {"  smtpPassword: " + plantPassword, plantPassword},
		"env: assignment":             {"VAULT_ROOT_KEK=" + plantToken, plantToken},
		"env: enc key":                {"TOTP_ENC_KEY=" + plantToken, plantToken},
		"env: dsn":                    {"dsn: postgres://u@db/x?password=" + plantPassword, plantPassword},
		"age key":                     {"key is " + plantAge, plantAge},
		"age key lower":               {"key is " + strings.ToLower(plantAge), strings.ToLower(plantAge)},
		"kubectl: last applied":       {`kubectl.kubernetes.io/last-applied-configuration: {"spec":{"value":"` + plantToken + `"}}`, plantToken},
		"describe: command line":      {"      --password=" + plantPassword, plantPassword},
		"pem: on one line":            {`{"key":"` + pemLine("BEGIN", "RSA ") + `\n` + plantPEMBody + `\n` + pemLine("END", "RSA ") + `"}`, plantPEMBody},
		"known value: nothing around": {"ready " + plantKnown + " done", plantKnown},
		"known value: inside a url":   {"http://x/" + plantKnown + "/y", plantKnown},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got := redactAll(t, NewRedactor([]string{plantKnown}, nil), c.in)
			if strings.Contains(got, c.gone) {
				t.Fatalf("%q survived: %q", c.gone, got)
			}
		})
	}
}

func TestRedactionRemovesAMultiLinePrivateKey(t *testing.T) {
	in := "before\n" + pemLine("BEGIN", "OPENSSH ") + "\n" + plantPEMBody + "\n" + plantPEMBody + "\n" + pemLine("END", "OPENSSH ") + "\nafter"
	got := redactAll(t, NewRedactor(nil, nil), in)
	if strings.Contains(got, plantPEMBody) {
		t.Fatalf("the key's body survived: %q", got)
	}
	if !strings.Contains(got, "before") || !strings.Contains(got, "after") {
		t.Fatalf("the lines around the key went too: %q", got)
	}
}

// A key with no END line withholds everything after it: it fails closed.
func TestAnUnterminatedPrivateKeyFailsClosed(t *testing.T) {
	got := redactAll(t, NewRedactor(nil, nil), pemLine("BEGIN", "")+"\n"+plantPEMBody+"\nmore "+plantPEMBody)
	if strings.Contains(got, plantPEMBody) {
		t.Fatalf("survived: %q", got)
	}
}

// kubectl describe prints each literal env value: only the names stay.
func TestDescribeEnvironmentKeepsNamesOnly(t *testing.T) {
	in := strings.Join([]string{
		"Containers:",
		"  gateway:",
		"    Image:      example.org/gateway:1.0",
		"    Environment:",
		"      LOG_LEVEL:   debug",
		"      DB_HOST:     " + plantToken,
		"      MULTI:       first",
		"                   " + plantPassword,
		"      FROM_SECRET: <set to the key 'k' in secret 's'>  Optional: false",
		"    Mounts:",
		"      /data from data (rw)",
	}, "\n")
	got := redactAll(t, NewRedactor(nil, nil), in)
	for _, gone := range []string{plantToken, plantPassword, "debug", "first"} {
		if strings.Contains(got, gone) {
			t.Fatalf("%q survived: %q", gone, got)
		}
	}
	for _, kept := range []string{"LOG_LEVEL:", "DB_HOST:", "MULTI:", "FROM_SECRET:", "/data from data (rw)", "example.org/gateway:1.0"} {
		if !strings.Contains(got, kept) {
			t.Fatalf("%q went missing: %q", kept, got)
		}
	}
}

func TestEnvironmentNoneDoesNotEatTheNextBlock(t *testing.T) {
	in := "    Environment:  <none>\n    Mounts:\n      /data from data (rw)"
	got := redactAll(t, NewRedactor(nil, nil), in)
	if got != in {
		t.Fatalf("got %q", got)
	}
}

func TestProductPatternsAddToTheBase(t *testing.T) {
	r := NewRedactor(nil, []*regexp.Regexp{regexp.MustCompile(`acct-[0-9]+`)})
	got, _ := r.Line("charged acct-12345 with token=" + plantToken)
	if strings.Contains(got, "acct-12345") || strings.Contains(got, plantToken) {
		t.Fatalf("got %q", got)
	}
}

// Diagnosis needs these; they look like secrets only to a careless pattern.
func TestRedactionKeepsWhatDiagnosisNeeds(t *testing.T) {
	for _, line := range []string{
		"sneakers   sneakers-box   Opaque   2   3d",
		"Warning  BackOff  pod/sneakers-vault-0  Back-off restarting failed container",
		"image: example.org/vault@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"    SecretName:  sneakers-box",
		"dial tcp 192.0.2.10:5432: connect: connection refused",
		"2026-10-30T12:00:00Z k0s-interim: prepare starts",
		"/dev/mapper/state on /var/lib/sneakers type ext4 (rw,relatime)",
	} {
		got, ok := NewRedactor(nil, nil).Line(line)
		if !ok || got != line {
			t.Fatalf("%q became %q", line, got)
		}
	}
}

// A log line can carry terminal escapes: copied out of an SSH session they
// would act on the reader's terminal.
func TestControlCharactersAreRemoved(t *testing.T) {
	got, _ := NewRedactor(nil, nil).Line("a\x1b[31mred\x1b[0m\x1b]0;title\x07 b\x00c\rd\te")
	if strings.ContainsAny(got, "\x1b\x00\r\x07") {
		t.Fatalf("got %q", got)
	}
	if !strings.Contains(got, "ared") || !strings.Contains(got, "\te") {
		t.Fatalf("the text went too: %q", got)
	}
}

// A known value shorter than a real secret is ignored, so a word such as
// "no" never goes.
func TestShortKnownValuesAreIgnored(t *testing.T) {
	got, _ := NewRedactor([]string{"no", ""}, nil).Line("no change, nothing to do")
	if got != "no change, nothing to do" {
		t.Fatalf("got %q", got)
	}
}
