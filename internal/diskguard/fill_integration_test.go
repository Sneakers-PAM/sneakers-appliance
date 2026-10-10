// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package diskguard_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/diskguard"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

// DISKGUARD_TEST_DIR names a directory on a small volume of its own (a
// tmpfs or a loop device, a few GiB at most), which the test fills past
// 80% and 90% and empties again:
//
//	sudo mount -t tmpfs -o size=256m tmpfs /mnt/dg && sudo chown "$USER" /mnt/dg
//	DISKGUARD_TEST_DIR=/mnt/dg go test -tags integration ./internal/diskguard/ -run Fill
const testDirEnv = "DISKGUARD_TEST_DIR"

func testVolume(t *testing.T) string {
	t.Helper()
	dir := os.Getenv(testDirEnv)
	if dir == "" {
		t.Skipf("set %s to a directory on a small tmpfs or loop volume", testDirEnv)
	}
	u, err := diskguard.Statfs(dir)
	mustNoErr(t, err)
	if u.Total > 8<<30 {
		t.Skipf("%s is %s; the test fills it, so give it one of 8 GiB or less", dir, diskguard.Bytes(int64(u.Total)))
	}
	root, err := os.MkdirTemp(dir, "diskguard-")
	mustNoErr(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

// fillTo writes files under dir until the volume is at pct, each up to
// chunk bytes, named by name(i), and backdated by age.
func fillTo(t *testing.T, vol string, pct float64, chunk int64, age time.Duration, name func(i int) string) {
	t.Helper()
	buf := make([]byte, 1<<20)
	for i := range buf {
		buf[i] = byte(i)
	}
	for i := 0; ; i++ {
		u, err := diskguard.Statfs(vol)
		mustNoErr(t, err)
		if u.Percent() >= pct {
			return
		}
		want := int64(float64(u.Used+u.Avail)*pct/100) - int64(u.Used)
		p := name(i)
		mustNoErr(t, os.MkdirAll(filepath.Dir(p), 0o700))
		f, err := os.Create(p)
		mustNoErr(t, err)
		for n := int64(0); n < min(want, chunk); n += int64(len(buf)) {
			if _, err := f.Write(buf); err != nil {
				break
			}
		}
		mustNoErr(t, f.Close())
		if age > 0 {
			old := time.Now().Add(-age)
			mustNoErr(t, os.Chtimes(p, old, old))
		}
	}
}

func fileSum(t *testing.T, p string) string {
	t.Helper()
	f, err := os.Open(p)
	mustNoErr(t, err)
	defer func() { _ = f.Close() }()
	h := sha256.New()
	_, err = io.Copy(h, f)
	mustNoErr(t, err)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func fillGuard(t *testing.T, root string, a *osaudit.Log) *diskguard.Guard {
	t.Helper()
	logs, uploads, stage, tmp := filepath.Join(root, "log"), filepath.Join(root, "uploads"), filepath.Join(root, "stage"), filepath.Join(root, "tmp")
	cleaner := &diskguard.Cleaner{
		Safety:    diskguard.Safety{Allowed: []string{logs, uploads, stage, tmp}, Protected: append(under(root, diskguard.BoxProtected), filepath.Join(root, "data"))},
		Audit:     a,
		StatePath: root,
		Steps: []diskguard.Step{
			diskguard.PodLogs{Dir: logs},
			diskguard.Updates{Uploads: uploads, StageDir: stage, Retention: 24 * time.Hour},
			diskguard.Tmp{Dir: tmp, Age: time.Hour},
		},
	}
	return &diskguard.Guard{
		Volumes:   []diskguard.Volume{{Name: "state", Label: "State", Path: root}},
		Cleaner:   cleaner,
		Audit:     a,
		StateFile: filepath.Join(t.TempDir(), "guard.json"),
	}
}

func actions(t *testing.T, a *osaudit.Log, from int) []string {
	t.Helper()
	es, err := a.Entries()
	mustNoErr(t, err)
	var out []string
	for _, e := range es[from:] {
		out = append(out, e.Action+":"+e.Detail["level"])
	}
	return out
}

// Filled past 80% with what the box may remove (rotated pod logs, an
// update upload nobody staged, stale temporary files), the volume
// recovers by itself in the same minute: the alert starts, the cleanup
// runs and frees it, and the alert clears, each audited.
func TestFillWithRemovableFilesRecovers(t *testing.T) {
	root := testVolume(t)
	a, err := osaudit.Open(t.TempDir(), osaudit.Options{})
	mustNoErr(t, err)
	g := fillGuard(t, root, a)
	g.Tick(context.Background())
	mark, _ := a.Entries()

	fillTo(t, root, 50, 32<<20, 2*time.Hour, func(i int) string {
		return filepath.Join(root, "log", "pods", "ns_pod_uid", "c", fmt.Sprintf("0.log.20261009-%06d.gz", i))
	})
	fillTo(t, root, 65, 64<<20, 48*time.Hour, func(i int) string { return filepath.Join(root, "uploads", fmt.Sprintf("up-%d.bin", i)) })
	fillTo(t, root, 85, 32<<20, 8*time.Hour, func(i int) string { return filepath.Join(root, "tmp", fmt.Sprintf("junk-%d", i)) })
	u, _ := diskguard.Statfs(root)
	t.Logf("filled to %.1f%%", u.Percent())

	r := g.Tick(context.Background())
	got := strings.Join(actions(t, a, len(mark)), " ")
	if !strings.HasPrefix(got, "disk.alert.start:warning disk.cleanup.run: disk.alert.clear:warning") {
		t.Fatalf("audit: %s", got)
	}
	if r.Volumes[0].Level != diskguard.LevelOK {
		t.Fatalf("after the cleanup: %+v", r.Volumes[0])
	}
	e, ok := lastAction(t, a, diskguard.ActionCleanup)
	if !ok || e.Detail["trigger"] != "alert" || e.Detail["freed.pod-logs"] == "0" || e.Detail["freed.updates"] == "0" || e.Detail["freed.tmp"] == "0" {
		t.Fatalf("the cleanup entry: %+v", e)
	}
	mustNoErr(t, a.Verify())
}

// Filled past 90% with a file the box must never remove (product data),
// the alert starts critical and stays after the cleanup, the file is
// untouched, and the alert clears only once the file is gone.
func TestFillWithAProtectedFileStaysCritical(t *testing.T) {
	root := testVolume(t)
	a, err := osaudit.Open(t.TempDir(), osaudit.Options{})
	mustNoErr(t, err)
	g := fillGuard(t, root, a)
	g.Tick(context.Background())
	mark, _ := a.Entries()

	keep := filepath.Join(root, "data", "keep")
	mustNoErr(t, os.MkdirAll(filepath.Dir(keep), 0o700))
	mustNoErr(t, os.WriteFile(keep, []byte("product data"), 0o600))
	keepSum := fileSum(t, keep)
	fill := filepath.Join(root, "data", "fill")
	fillTo(t, root, 92, 1<<40, 30*24*time.Hour, func(int) string { return fill + fmt.Sprint(time.Now().UnixNano()) })
	fills, _ := filepath.Glob(fill + "*")
	sums := map[string]string{}
	for _, f := range fills {
		sums[f] = fileSum(t, f)
	}

	r := g.Tick(context.Background())
	if got := strings.Join(actions(t, a, len(mark)), " "); got != "disk.alert.start:critical disk.cleanup.run:" {
		t.Fatalf("audit: %s", got)
	}
	if r.Volumes[0].Level != diskguard.LevelCritical || len(r.Warnings) == 0 || !r.Warnings[0].Critical {
		t.Fatalf("%+v %+v", r.Volumes[0], r.Warnings)
	}
	if fileSum(t, keep) != keepSum {
		t.Fatal("the protected file changed")
	}
	for f, s := range sums {
		if fileSum(t, f) != s {
			t.Fatalf("%s changed", f)
		}
	}

	for _, f := range fills {
		mustNoErr(t, os.Remove(f))
	}
	g.Tick(context.Background())
	got := actions(t, a, len(mark))
	if last := got[len(got)-1]; last != "disk.alert.clear:critical" {
		t.Fatalf("audit after the file went: %v", got)
	}
	mustNoErr(t, a.Verify())
}

func lastAction(t *testing.T, a *osaudit.Log, action string) (osaudit.Entry, bool) {
	t.Helper()
	es, err := a.Entries()
	mustNoErr(t, err)
	for i := len(es) - 1; i >= 0; i-- {
		if es[i].Action == action {
			return es[i], true
		}
	}
	return osaudit.Entry{}, false
}
