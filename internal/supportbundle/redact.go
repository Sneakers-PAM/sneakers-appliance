// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package supportbundle

import (
	"regexp"
	"strings"
	"unicode"
)

// Mask stands where a secret was.
const Mask = "[redacted]"

// maskKey is the one line left of a multi-line private key.
const maskKey = "[redacted private key]"

// minKnown is the shortest known value matched by value: anything shorter
// is a word, not a secret the box generated.
const minKnown = 8

var (
	escapes = regexp.MustCompile(`\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b.`)

	pemBegin  = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`)
	pemEnd    = regexp.MustCompile(`-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`)
	pemInline = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|$)`)

	// wholeRest are the headers whose whole value is a credential, and the
	// annotation that repeats a manifest: everything to the end of the
	// line goes, since a header's value has no reliable end.
	wholeRest = regexp.MustCompile(`(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-vault-token|last-applied-configuration)(\\?["']?\s*[:=]\s*).*$`)

	urlPassword = regexp.MustCompile(`(://[^/\s:@]*):[^\s@]+@`)

	// keyed is key=value and key: value, quoted or bare, where the key
	// says the value is secret.
	keyed = regexp.MustCompile(`(?i)(\\?["']?)([a-z0-9_.\-]*(?:password|passwd|pwd|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|\bkek\b|_kek\b|enc[_-]?key|signature)[a-z0-9_.\-]*)(\\?["']?\s*[:=]\s*)(\\"(?:[^"\\]|\\[^"])*\\"|"(?:[^"\\]|\\.)*"|'[^']*'|[^\s,;&}\])]+)`)

	values = []*regexp.Regexp{
		regexp.MustCompile(`\bsnk_[A-Za-z0-9_\-]+`),
		regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]*)?`),
		regexp.MustCompile(`(?i)\bage-secret-key-1[a-z0-9]+`),
		regexp.MustCompile(`\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]+`),
		regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=\-]+`),
		regexp.MustCompile(`\b[Bb]asic\s+[A-Za-z0-9+/]{8,}={0,2}`),
	}

	envHeading = regexp.MustCompile(`^(\s*)Environment:\s*$`)
	envEntry   = regexp.MustCompile(`^(\s+[A-Za-z_][A-Za-z0-9_.\-]*:)`)
)

// Redactor removes secrets from one section's lines, in order: it holds
// the state a private key or a describe's Environment block spans. Every
// line of a bundle passes one before it's written, so its use is the
// safety of the bundle.
type Redactor struct {
	known []string
	extra []*regexp.Regexp
	// inKey is true inside a multi-line private key. A key with no END
	// line withholds the rest of the section.
	inKey bool
	// inEnv is true inside a describe's Environment block, whose indent is
	// envIndent.
	inEnv     bool
	envIndent int
}

// NewRedactor returns a redactor for one section. known are values the box
// knows are secret (what it generated for the product), matched as they
// are; extra are the section's own patterns, which can only add to these.
func NewRedactor(known []string, extra []*regexp.Regexp) *Redactor {
	r := &Redactor{extra: extra}
	for _, k := range known {
		if len(k) >= minKnown {
			r.known = append(r.known, k)
		}
	}
	return r
}

// Line returns line as it may be written; ok is false when none of it
// may.
func (r *Redactor) Line(line string) (string, bool) {
	line = printable(line)
	if r.inKey {
		if pemEnd.MatchString(line) {
			r.inKey = false
		}
		return "", false
	}
	if pemBegin.MatchString(line) {
		if !pemEnd.MatchString(line) && !strings.Contains(line, `\n`) {
			r.inKey = true
			return maskKey, true
		}
		line = pemInline.ReplaceAllString(line, maskKey)
	}
	if l, ok, done := r.environment(line); done {
		return l, ok
	}
	return r.scrub(line), true
}

// environment handles a line inside, or starting, a describe's Environment
// block: every value goes, and with it a value's further lines, so only
// the names stay. done is false for a line outside one.
func (r *Redactor) environment(line string) (out string, ok, done bool) {
	if m := envHeading.FindStringSubmatch(line); m != nil {
		r.inEnv, r.envIndent = true, len(m[1])
		return line, true, true
	}
	if !r.inEnv {
		return "", false, false
	}
	indent := len(line) - len(strings.TrimLeft(line, " \t"))
	if indent <= r.envIndent && strings.TrimSpace(line) != "" {
		r.inEnv = false
		return "", false, false
	}
	if m := envEntry.FindStringSubmatch(line); m != nil {
		return m[1] + " " + Mask, true, true
	}
	return "", false, true
}

func (r *Redactor) scrub(line string) string {
	for _, k := range r.known {
		line = strings.ReplaceAll(line, k, Mask)
	}
	line = wholeRest.ReplaceAllString(line, "${1}${2}"+Mask)
	line = urlPassword.ReplaceAllString(line, "${1}:"+Mask+"@")
	line = keyed.ReplaceAllStringFunc(line, func(m string) string {
		p := keyed.FindStringSubmatch(m)
		if notSecretKey(p[2]) {
			return m
		}
		return p[1] + p[2] + p[3] + Mask
	})
	for _, re := range values {
		line = re.ReplaceAllString(line, Mask)
	}
	for _, re := range r.extra {
		line = re.ReplaceAllString(line, Mask)
	}
	return line
}

// notSecretKey is true for a key that names a secret instead of holding
// one (secretName, secretKeyRef, token_type): the name helps a diagnosis
// and the bundle shows Secrets by name anyway.
func notSecretKey(key string) bool {
	k := strings.ToLower(key)
	for _, s := range []string{"name", "ref", "type"} {
		if strings.HasSuffix(k, s) {
			return true
		}
	}
	return false
}

// printable takes out terminal escapes, control characters and bytes that
// aren't text. A tab stays.
func printable(s string) string {
	if strings.IndexFunc(s, func(c rune) bool { return c == unicode.ReplacementChar || unicode.IsControl(c) && c != '\t' }) < 0 && strings.ToValidUTF8(s, "") == s {
		return s
	}
	s = escapes.ReplaceAllString(strings.ToValidUTF8(s, ""), "")
	return strings.Map(func(c rune) rune {
		if unicode.IsControl(c) && c != '\t' {
			return -1
		}
		return c
	}, s)
}
