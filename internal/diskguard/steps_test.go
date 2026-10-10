// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package diskguard_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/diskguard"
)

func env(root string, allowed ...string) diskguard.Env {
	return diskguard.Env{Now: time.Now(), Logger: log.Nop(),
		Safety: diskguard.Safety{Allowed: allowed, Protected: under(root, diskguard.BoxProtected)}}
}

// Rotated pod logs go oldest first and only until the logs are within
// their cap and the volume above its floor.
func TestPodLogsKeepWithinCap(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "var/lib/log")
	base := time.Now().Add(-10 * time.Hour)
	for i := range 6 {
		write(t, filepath.Join(dir, "pods", "p", "c", fmt.Sprintf("0.log.%d", i)), 4096, base.Add(time.Duration(i)*time.Hour))
	}
	write(t, filepath.Join(dir, "pods", "p", "c", "0.log"), 4096, time.Time{})
	e := env(root, dir)
	e.State = diskguard.Usage{Total: 1 << 40, Avail: 1 << 39}
	res, err := diskguard.PodLogs{Dir: dir, Cap: 4 * 4096}.Clean(context.Background(), e)
	mustNoErr(t, err)
	if res.Freed != 3*4096 {
		t.Fatalf("freed %d", res.Freed)
	}
	for i := range 6 {
		_, err := os.Stat(filepath.Join(dir, "pods", "p", "c", fmt.Sprintf("0.log.%d", i)))
		if gone := os.IsNotExist(err); gone != (i < 3) {
			t.Fatalf("0.log.%d gone=%v", i, gone)
		}
	}
	// Under the floor, every rotated log goes but the live one stays.
	e.State.Avail = 1
	_, err = diskguard.PodLogs{Dir: dir, Cap: 1 << 30, KeepFree: 1 << 30}.Clean(context.Background(), e)
	mustNoErr(t, err)
	left, _ := filepath.Glob(filepath.Join(dir, "pods", "p", "c", "*"))
	if len(left) != 1 || filepath.Base(left[0]) != "0.log" {
		t.Fatalf("left %v", left)
	}
}

// A recent upload stays, an old one goes, and nothing goes while an
// update is coming in or staging.
func TestUpdatesRetention(t *testing.T) {
	root := t.TempDir()
	up, stage := filepath.Join(root, "uploads"), filepath.Join(root, "stage")
	old := time.Now().Add(-8 * 24 * time.Hour)
	write(t, filepath.Join(up, "up-old.bin"), 100, old)
	mustNoErr(t, os.WriteFile(filepath.Join(up, "up-old.json"), fmt.Appendf(nil, `{"at":%q}`, old.Format(time.RFC3339)), 0o600))
	write(t, filepath.Join(up, "up-new.bin"), 100, time.Time{})
	write(t, filepath.Join(up, "up-new.tmp"), 100, time.Time{})
	busy := true
	u := diskguard.Updates{Uploads: up, StageDir: stage, Retention: 7 * 24 * time.Hour, Busy: func() bool { return busy }}
	if res, err := u.Clean(context.Background(), env(root, up, stage)); err != nil || res.Freed != 0 || !strings.Contains(res.Note, "skipped") {
		t.Fatalf("busy: %+v %v", res, err)
	}
	busy = false
	_, err := u.Clean(context.Background(), env(root, up, stage))
	mustNoErr(t, err)
	left, _ := filepath.Glob(filepath.Join(up, "*"))
	if len(left) != 2 || !strings.HasSuffix(left[0], "up-new.bin") || !strings.HasSuffix(left[1], "up-new.tmp") {
		t.Fatalf("left %v", left)
	}
}

// Images keeps what a container uses and what containerd pins, and with
// no release image found removes nothing at all.
func TestImagesKeepsWhatIsNeeded(t *testing.T) {
	root := t.TempDir()
	slot := filepath.Join(root, "a")
	k0s := filepath.Join(slot, "k0s")
	write(t, k0s, 1, time.Time{})
	list := "REF TYPE DIGEST SIZE PLATFORMS LABELS\n" +
		"r/run:1 m sha256:" + strings.Repeat("1", 64) + " 1 MiB linux/amd64 -\n" +
		"r/pin:1 m sha256:" + strings.Repeat("2", 64) + " 1 MiB linux/amd64 io.cri-containerd.image=managed,io.cri-containerd.pinned=pinned\n" +
		"r/cfg:1 m sha256:" + strings.Repeat("3", 64) + " 1 MiB linux/amd64 -\n" +
		"r/slot:1 m sha256:" + strings.Repeat("4", 64) + " 1 MiB linux/amd64 -\n" +
		"r/gone:1 m sha256:" + strings.Repeat("5", 64) + " 1 MiB linux/amd64 -\n"
	cfg := filepath.Join(root, "k0s.yaml")
	mustNoErr(t, os.WriteFile(cfg, []byte("image: x@sha256:"+strings.Repeat("3", 64)+"\n"), 0o600))
	var removed []string
	im := diskguard.Images{K0s: k0s, Containerd: "/sock", Slots: []string{slot}, Pinned: []string{cfg},
		Run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			switch strings.Join(args[5:], " ") {
			case "images list":
				return []byte(list), nil
			case "containers list":
				return []byte("CONTAINER IMAGE RUNTIME\nabc r/run:1 io.containerd.runc.v2\n"), nil
			}
			removed = append(removed, args[5:]...)
			return nil, nil
		}}
	res, err := im.Clean(context.Background(), env(root))
	mustNoErr(t, err)
	if !strings.Contains(res.Note, "no release images") || removed != nil {
		t.Fatalf("no slot images: %+v %v", res, removed)
	}
	write(t, filepath.Join(slot, "images", strings.Repeat("4", 64)+".tar"), 1, time.Time{})
	_, err = im.Clean(context.Background(), env(root))
	mustNoErr(t, err)
	if strings.Join(removed, " ") != "images rm --sync r/gone:1" {
		t.Fatalf("removed %v", removed)
	}
}

func TestTmpTakesOnlyOldFiles(t *testing.T) {
	root := t.TempDir()
	tmp := filepath.Join(root, "tmp")
	write(t, filepath.Join(tmp, "old"), 10, time.Now().Add(-8*24*time.Hour))
	write(t, filepath.Join(tmp, "new"), 10, time.Time{})
	res, err := diskguard.Tmp{Dir: tmp, Age: 7 * 24 * time.Hour}.Clean(context.Background(), env(root, tmp))
	mustNoErr(t, err)
	if _, err := os.Stat(filepath.Join(tmp, "new")); err != nil || res.Freed == 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "old")); !os.IsNotExist(err) {
		t.Fatal("the old file is still there")
	}
}

func TestLogCaps(t *testing.T) {
	if diskguard.LogCap(64<<30) != (64<<30)/50 {
		t.Fatalf("64 GiB: %d", diskguard.LogCap(64<<30))
	}
	if diskguard.LogCap(1<<30) != 256<<20 || diskguard.LogCap(1<<40) != 2<<30 {
		t.Fatal("the cap isn't held between 256 MiB and 2 GiB")
	}
	if diskguard.LogKeepFree(1<<30) != 1<<30 || diskguard.LogKeepFree(1<<40) != 16<<30 {
		t.Fatal("the floor isn't held between 1 GiB and 16 GiB")
	}
}
