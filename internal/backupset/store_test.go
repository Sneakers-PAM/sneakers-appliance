// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package backupset

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSegmentNames(t *testing.T) {
	for lsn, want := range map[string]string{
		"0/7012438":   "000000010000000000000007",
		"0/FF000000":  "0000000100000000000000FF",
		"1/0":         "000000010000000100000000",
		"2A/3B000028": "000000010000002A0000003B",
	} {
		l, err := parseLSN(lsn)
		if err != nil {
			t.Fatal(err)
		}
		if got := segmentName(1, segmentNo(l)); got != want {
			t.Errorf("%s: %s, want %s", lsn, got, want)
		}
	}
	if _, err := parseLSN("nonsense"); err == nil {
		t.Fatal("nonsense read as an LSN")
	}
}

func writeStore(t *testing.T, store string, names ...string) {
	t.Helper()
	for _, n := range names {
		p := filepath.Join(store, n)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		body := "wal " + n
		if strings.HasSuffix(n, sentinelSuffix) {
			body = `{"LSN":33554520,"PgVersion":180006,"SystemIdentifier":77,"UncompressedSize":1048576,"FinishTime":"2026-11-01T19:50:09.035725Z"}`
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestChainNamesTheFirstMissingSegment(t *testing.T) {
	store := t.TempDir()
	writeStore(t, store,
		"basebackups_005/base_000000010000000000000002"+sentinelSuffix,
		"basebackups_005/base_000000010000000000000002/tar_partitions/part_001.tar.lz4",
		"basebackups_005/base_000000030000000000000002_unfinished/x",
		"wal_005/000000010000000000000002.00000058.backup.lz4",
		"wal_005/000000010000000000000002.lz4",
		"wal_005/000000010000000000000004.lz4",
		"wal_005/000000010000000000000003.lz4.tmp.20261101T194433Z-63f0",
	)
	bs, err := bases(store)
	if err != nil || len(bs) != 1 || bs[0].Timeline != 1 || bs[0].StartLSN != 33554520 {
		t.Fatalf("bases = %+v, %v", bs, err)
	}
	have, err := segments(store)
	if err != nil {
		t.Fatal(err)
	}
	if got := have["000000010000000000000002"]; got != "000000010000000000000002.lz4" {
		t.Fatalf("segment 2 is %q", got)
	}
	point := uint64(4 * segmentBytes)
	if _, err := chain(have, bs[0], 1, point); err == nil || !strings.Contains(err.Error(), "000000010000000000000003") {
		t.Fatalf("a segment WAL-G never finished counted: %v", err)
	}
	writeStore(t, store, "wal_005/000000010000000000000003.lz4")
	if have, err = segments(store); err != nil {
		t.Fatal(err)
	}
	got, err := chain(have, bs[0], 1, point)
	if err != nil || len(got) != 3 {
		t.Fatalf("chain = %v, %v", got, err)
	}
	if _, err := chain(have, bs[0], 2, point); err == nil {
		t.Fatal("a point on another timeline passed")
	}
}
