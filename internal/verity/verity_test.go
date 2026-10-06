// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package verity_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/verity"
)

func randomImage(t *testing.T, blocks int) []byte {
	t.Helper()
	b := make([]byte, blocks*verity.BlockSize)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRootHashMatchesVeritysetup formats images with the real veritysetup
// and checks the pure-Go tree, byte for byte, and the root hash.
func TestRootHashMatchesVeritysetup(t *testing.T) {
	bin, err := exec.LookPath("veritysetup")
	if err != nil {
		if os.Getenv("SNEAKERS_REQUIRE_TOOLS") != "" {
			t.Fatal("veritysetup isn't installed and SNEAKERS_REQUIRE_TOOLS is set")
		}
		t.Skip("veritysetup isn't installed; CI installs it")
	}
	for _, blocks := range []int{1, 2, 129, 300, 16500} {
		t.Run(strconv.Itoa(blocks), func(t *testing.T) {
			data := randomImage(t, blocks)
			img := filepath.Join(t.TempDir(), "root.img")
			if err := os.WriteFile(img, data, 0o600); err != nil {
				t.Fatal(err)
			}
			offset := int64(len(data))
			out, err := exec.Command(bin, "format", "--hash-offset="+strconv.FormatInt(offset, 10), img, img).CombinedOutput() // #nosec G204 -- test-only, fixed tool
			if err != nil {
				t.Fatalf("veritysetup: %v\n%s", err, out)
			}
			m := regexp.MustCompile(`Root hash:\s+([0-9a-f]{64})`).FindSubmatch(out)
			if m == nil {
				t.Fatalf("no root hash in\n%s", out)
			}
			f, err := os.Open(img) // #nosec G304 -- the test's own temp file
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			st, _ := f.Stat()
			got, err := verity.RootHash(f, st.Size(), offset)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != string(m[1]) {
				t.Fatalf("root hash %x, veritysetup says %s", got, m[1])
			}
		})
	}
}

func TestFormatThenRootHash(t *testing.T) {
	data := randomImage(t, 300)
	area, root, err := verity.Format(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	img := append(append([]byte(nil), data...), area...)
	got, err := verity.RootHash(bytes.NewReader(img), int64(len(img)), int64(len(data)))
	if err != nil || !bytes.Equal(got, root) {
		t.Fatalf("got %x want %x (%v)", got, root, err)
	}
}

func TestFlippedByteChangesTheTree(t *testing.T) {
	data := randomImage(t, 300)
	area, _, err := verity.Format(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	img := append(append([]byte(nil), data...), area...)
	img[12345] ^= 0x01
	if _, err := verity.RootHash(bytes.NewReader(img), int64(len(img)), int64(len(data))); !errors.Is(err, verity.ErrMismatch) {
		t.Fatalf("data byte: %v", err)
	}
	img[12345] ^= 0x01
	img[len(data)+verity.BlockSize+7] ^= 0x01
	if _, err := verity.RootHash(bytes.NewReader(img), int64(len(img)), int64(len(data))); !errors.Is(err, verity.ErrMismatch) {
		t.Fatalf("tree byte: %v", err)
	}
}

func TestRefusesAMissingSuperblock(t *testing.T) {
	data := randomImage(t, 4)
	if _, err := verity.RootHash(bytes.NewReader(data), int64(len(data)), 2*verity.BlockSize); err == nil {
		t.Fatal("no superblock")
	}
}
