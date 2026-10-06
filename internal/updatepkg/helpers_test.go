// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package updatepkg_test

import (
	"archive/tar"
	"bytes"
	"testing"
	"time"
)

var timeZero = time.Unix(0, 0)

func evilTar(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	body := []byte("x")
	if err := tw.WriteHeader(&tar.Header{Name: "../escape", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
