// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

const feedTime = "2026-11-18T12:00:00Z"

// feedRelease writes a release directory as the release publishes it: the
// index, its SHA256SUMS (one line per listed file) and both signatures.
// Each entry is a product of the given version.
func feedRelease(t *testing.T, root, tag string, key testpki.ECKey, versions ...string) string {
	t.Helper()
	dir := filepath.Join(root, tag)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	var idx updatepkg.Index
	idx.Format = updatepkg.IndexFormat
	var sums strings.Builder
	for _, v := range versions {
		file := fmt.Sprintf("sneakers-product-%s-amd64.bin", v)
		idx.Products = append(idx.Products, updatepkg.IndexEntry{Version: v, Arch: "amd64", Channel: "production", Bases: []string{v}, MinBase: v, File: file, Size: 1000})
		sum := sha256.Sum256([]byte(file))
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(sum[:]), file)
	}
	b, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	signFeedFile(t, dir, updatepkg.IndexName, b, key)
	signFeedFile(t, dir, "SHA256SUMS", []byte(sums.String()), key)
	return dir
}

func signFeedFile(t *testing.T, dir, name string, data []byte, key testpki.ECKey) {
	t.Helper()
	writeFile(t, filepath.Join(dir, name), data)
	writeFile(t, filepath.Join(dir, name+".sigstore.json"), key.BlobBundle(t, data))
}

type feedSetup struct {
	root, keyFile, withdrawn string
	key                      testpki.ECKey
}

func newFeedSetup(t *testing.T) feedSetup {
	t.Helper()
	tmp := t.TempDir()
	s := feedSetup{root: filepath.Join(tmp, "releases"), keyFile: filepath.Join(tmp, "cosign.pub"), withdrawn: filepath.Join(tmp, "withdrawn.yaml"), key: testpki.ECDSA(t)}
	if err := os.MkdirAll(s.root, 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, s.keyFile, s.key.PublicPEM)
	writeFile(t, s.withdrawn, []byte("- kind: product\n  version: 0.1.0-rc.9\n  reason: an update from rc.6 fails; use rc.10\n  use: 0.1.0-rc.10\n"))
	return s
}

func (s feedSetup) run(t *testing.T, out string, extra ...string) error {
	t.Helper()
	args := append([]string{"feed-index", "--release-key", s.keyFile, "--releases", s.root, "--withdrawn", s.withdrawn, "--generated-at", feedTime, "--out", out}, extra...)
	_, err := runCmd(t, args...)
	return err
}

func readFeed(t *testing.T, p string) updatepkg.Index {
	t.Helper()
	b, err := os.ReadFile(p) // #nosec G304 -- the test's own output
	if err != nil {
		t.Fatal(err)
	}
	var idx updatepkg.Index
	if err := json.Unmarshal(b, &idx); err != nil {
		t.Fatal(err)
	}
	return idx
}

func TestFeedIndexMergesTheReleasesAndTheWithdrawnList(t *testing.T) {
	s := newFeedSetup(t)
	feedRelease(t, s.root, "v0.1.0-rc.9", s.key, "0.1.0-rc.9")
	feedRelease(t, s.root, "v0.1.0-rc.10", s.key, "0.1.0-rc.10")
	out := filepath.Join(t.TempDir(), "index.json")
	if err := s.run(t, out, "--channel", "rc"); err != nil {
		t.Fatal(err)
	}
	idx := readFeed(t, out)
	if idx.Format != 2 || idx.Feed == nil || *idx.Feed != (updatepkg.FeedMeta{Channel: "rc", Sequence: 1, GeneratedAt: feedTime}) {
		t.Fatalf("format %d, feed %+v", idx.Format, idx.Feed)
	}
	if len(idx.Products) != 2 || idx.Products[0].Version != "0.1.0-rc.10" || idx.Products[1].Version != "0.1.0-rc.9" {
		t.Fatalf("products, newest first: %+v", idx.Products)
	}
	e := idx.Products[0]
	if e.Tag != "v0.1.0-rc.10" || e.Docs != "https://docs.sneakers-pam.com/v0.1.0-rc.10/" || e.File != "sneakers-product-0.1.0-rc.10-amd64.bin" || e.Size != 1000 {
		t.Fatalf("entry %+v", e)
	}
	if len(idx.Withdrawn) != 1 || idx.Withdrawn[0].Version != "0.1.0-rc.9" || idx.Withdrawn[0].Use != "0.1.0-rc.10" {
		t.Fatalf("withdrawn %+v", idx.Withdrawn)
	}
	b, _ := os.ReadFile(out) // #nosec G304 -- the test's own output
	if !strings.HasSuffix(string(b), "}\n") || !strings.Contains(string(b), "\n  \"feed\": {") {
		t.Fatalf("not indented JSON with a trailing newline:\n%s", b)
	}
}

func TestFeedIndexTakesTheSequenceFromPreviousOrTheFlag(t *testing.T) {
	s := newFeedSetup(t)
	feedRelease(t, s.root, "v0.1.0-rc.10", s.key, "0.1.0-rc.10")
	dir := t.TempDir()
	prev := filepath.Join(dir, "previous.json")
	writeFile(t, prev, []byte(`{"format":2,"feed":{"channel":"rc","sequence":17,"generated_at":"2026-11-01T00:00:00Z"},"products":[]}`))
	out := filepath.Join(dir, "index.json")
	if err := s.run(t, out, "--channel", "rc", "--previous", prev); err != nil {
		t.Fatal(err)
	}
	if got := readFeed(t, out).Feed.Sequence; got != 18 {
		t.Fatalf("sequence %d, want 18", got)
	}
	if err := s.run(t, out, "--channel", "rc", "--sequence", "40"); err != nil {
		t.Fatal(err)
	}
	if got := readFeed(t, out).Feed.Sequence; got != 40 {
		t.Fatalf("sequence %d, want 40", got)
	}
	if err := s.run(t, out, "--channel", "rc", "--sequence", "40", "--previous", prev); err == nil {
		t.Fatal("both --sequence and --previous were taken")
	}
	writeFile(t, prev, []byte(`{"format":2,"products":[]}`))
	if err := s.run(t, out, "--channel", "rc", "--previous", prev); err == nil {
		t.Fatal("a previous feed with no sequence was taken")
	}
}

func TestFeedIndexRefusesABadSignatureNamingTheRelease(t *testing.T) {
	s := newFeedSetup(t)
	feedRelease(t, s.root, "v0.1.0-rc.10", s.key, "0.1.0-rc.10")
	feedRelease(t, s.root, "v0.1.0-rc.9", testpki.ECDSA(t), "0.1.0-rc.9")
	out := filepath.Join(t.TempDir(), "index.json")
	err := s.run(t, out, "--channel", "rc")
	if err == nil || !strings.Contains(err.Error(), "v0.1.0-rc.9") || strings.Contains(err.Error(), "v0.1.0-rc.10") {
		t.Fatalf("a release signed by another key: %v", err)
	}
	if _, serr := os.Stat(out); serr == nil {
		t.Fatal("an index was written despite the refusal")
	}

	// A SHA256SUMS changed after it was signed is refused the same way.
	s2 := newFeedSetup(t)
	dir := feedRelease(t, s2.root, "v0.1.0-rc.10", s2.key, "0.1.0-rc.10")
	writeFile(t, filepath.Join(dir, "SHA256SUMS"), []byte("00  sneakers-product-0.1.0-rc.10-amd64.bin\n"))
	err = s2.run(t, out, "--channel", "rc")
	if err == nil || !strings.Contains(err.Error(), "v0.1.0-rc.10") || !strings.Contains(err.Error(), "SHA256SUMS") {
		t.Fatalf("a SHA256SUMS that isn't the signed one: %v", err)
	}
}

func TestFeedIndexRefusesAFileMissingFromSHA256SUMS(t *testing.T) {
	s := newFeedSetup(t)
	dir := feedRelease(t, s.root, "v0.1.0-rc.10", s.key, "0.1.0-rc.10")
	signFeedFile(t, dir, "SHA256SUMS", []byte("00  something-else.bin\n"), s.key)
	err := s.run(t, filepath.Join(t.TempDir(), "index.json"), "--channel", "rc")
	if err == nil || !strings.Contains(err.Error(), "v0.1.0-rc.10") || !strings.Contains(err.Error(), "sneakers-product-0.1.0-rc.10-amd64.bin") {
		t.Fatalf("a listed file with no checksum line: %v", err)
	}
}

func TestFeedIndexRefusesAnEntryWithNoSize(t *testing.T) {
	s := newFeedSetup(t)
	dir := feedRelease(t, s.root, "v0.1.0-rc.10", s.key, "0.1.0-rc.10")
	b, err := os.ReadFile(filepath.Join(dir, updatepkg.IndexName)) // #nosec G304 -- the test's own output
	if err != nil {
		t.Fatal(err)
	}
	signFeedFile(t, dir, updatepkg.IndexName, []byte(strings.Replace(string(b), `"size": 1000`, `"size": 0`, 1)), s.key)
	err = s.run(t, filepath.Join(t.TempDir(), "index.json"), "--channel", "rc")
	if err == nil || !strings.Contains(err.Error(), "v0.1.0-rc.10") || !strings.Contains(err.Error(), "size") {
		t.Fatalf("an entry of size 0: %v", err)
	}
}

func TestFeedIndexKeepsOnlyTheChannelsReleases(t *testing.T) {
	s := newFeedSetup(t)
	feedRelease(t, s.root, "v0.1.0-rc.10", s.key, "0.1.0-rc.10")
	feedRelease(t, s.root, "v0.1.0", s.key, "0.1.0")
	feedRelease(t, s.root, "v0.1.1-lab.1", s.key, "0.1.1-lab.1")
	out := filepath.Join(t.TempDir(), "index.json")
	versions := func(channel string) string {
		t.Helper()
		if err := s.run(t, out, "--channel", channel); err != nil {
			t.Fatal(err)
		}
		var v []string
		for _, e := range readFeed(t, out).Products {
			v = append(v, e.Version)
		}
		return strings.Join(v, ",")
	}
	if got := versions("rc"); got != "0.1.0,0.1.0-rc.10" {
		t.Fatalf("rc feed: %s", got)
	}
	if got := versions("stable"); got != "0.1.0" {
		t.Fatalf("stable feed: %s", got)
	}
	if err := s.run(t, out, "--channel", "nightly"); err == nil {
		t.Fatal("a channel that isn't rc or stable was taken")
	}
}

func TestFeedIndexKeepsTheNewerReleasesEntryForAVersionTwoListed(t *testing.T) {
	s := newFeedSetup(t)
	feedRelease(t, s.root, "v0.1.0-rc.9", s.key, "0.1.0-rc.9")
	feedRelease(t, s.root, "v0.1.0-rc.10", s.key, "0.1.0-rc.10", "0.1.0-rc.9")
	out := filepath.Join(t.TempDir(), "index.json")
	if err := s.run(t, out, "--channel", "rc"); err != nil {
		t.Fatal(err)
	}
	idx := readFeed(t, out)
	if len(idx.Products) != 2 {
		t.Fatalf("products %+v", idx.Products)
	}
	for _, e := range idx.Products {
		if e.Version == "0.1.0-rc.9" && e.Tag != "v0.1.0-rc.10" {
			t.Fatalf("rc.9 comes from %s, want the newer release", e.Tag)
		}
	}
}

func TestFeedIndexIsDeterministic(t *testing.T) {
	s := newFeedSetup(t)
	feedRelease(t, s.root, "v0.1.0-rc.9", s.key, "0.1.0-rc.9")
	feedRelease(t, s.root, "v0.1.0-rc.10", s.key, "0.1.0-rc.10")
	feedRelease(t, s.root, "v0.1.0", s.key, "0.1.0")
	dir := t.TempDir()
	var first []byte
	for i := range 3 {
		out := filepath.Join(dir, fmt.Sprintf("index%d.json", i))
		if err := s.run(t, out, "--channel", "rc", "--sequence", "5", "--docs-url-template", "https://docs.sneakers-pam.com/{version}/"); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(out) // #nosec G304 -- the test's own output
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = b
		} else if string(b) != string(first) {
			t.Fatalf("run %d differs:\n%s\n%s", i, b, first)
		}
	}
	if !strings.Contains(string(first), `"docs": "https://docs.sneakers-pam.com/0.1.0-rc.10/"`) {
		t.Fatalf("the docs template:\n%s", first)
	}
}

func TestFeedIndexRefusesAWithdrawnListThatFailsValidation(t *testing.T) {
	s := newFeedSetup(t)
	feedRelease(t, s.root, "v0.1.0-rc.10", s.key, "0.1.0-rc.10")
	writeFile(t, s.withdrawn, []byte("- kind: firmware\n  version: 0.1.0-rc.9\n  reason: r\n"))
	out := filepath.Join(t.TempDir(), "index.json")
	if err := s.run(t, out, "--channel", "rc"); err == nil {
		t.Fatal("a withdrawn list with a kind that isn't one was published")
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("an index was written despite the refusal")
	}
}

func TestFeedIndexTakesTheRepositorysWithdrawnList(t *testing.T) {
	s := newFeedSetup(t)
	feedRelease(t, s.root, "v0.1.0-rc.10", s.key, "0.1.0-rc.10")
	s.withdrawn = "../../release/withdrawn.yaml"
	if err := s.run(t, filepath.Join(t.TempDir(), "index.json"), "--channel", "rc"); err != nil {
		t.Fatal(err)
	}
}
