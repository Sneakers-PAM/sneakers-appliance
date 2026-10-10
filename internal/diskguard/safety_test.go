// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package diskguard_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/diskguard"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, p string, size int, mod time.Time) {
	t.Helper()
	mustNoErr(t, os.MkdirAll(filepath.Dir(p), 0o700))
	mustNoErr(t, os.WriteFile(p, []byte(strings.Repeat("z", size)), 0o600))
	if !mod.IsZero() {
		mustNoErr(t, os.Chtimes(p, mod, mod))
	}
}

// under puts the box's paths under root.
func under(root string, ps []string) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = filepath.Join(root, p)
	}
	return out
}

func TestSafetyRefuses(t *testing.T) {
	root := t.TempDir()
	s := diskguard.Safety{
		Allowed:   under(root, []string{"/var/lib/log", "/tmp"}),
		Protected: under(root, diskguard.BoxProtected),
	}
	mustNoErr(t, os.MkdirAll(filepath.Join(root, "var/lib/sneakers-data/db"), 0o700))
	mustNoErr(t, os.MkdirAll(filepath.Join(root, "var/lib/log"), 0o700))
	// A link inside an allowed root that leads into product data.
	mustNoErr(t, os.Symlink(filepath.Join(root, "var/lib/sneakers-data/db"), filepath.Join(root, "var/lib/log/db")))
	for _, p := range []string{
		filepath.Join(root, "var/lib/sneakers-data"),
		filepath.Join(root, "var/lib/sneakers-data/db/base/1"),
		filepath.Join(root, "var/lib/sneakers"),
		filepath.Join(root, "var/lib/sneakers/backup/escrow/escrow.age"),
		filepath.Join(root, "var/lib/sneakers/product/a/images/x.tar"),
		filepath.Join(root, "var/lib/k0s/etcd/member"),
		filepath.Join(root, "var/lib/log"),
		filepath.Join(root, "var/lib/log/db/base/1"),
		filepath.Join(root, "etc/passwd"),
		filepath.Join(root, "var/lib/log/../sneakers-data/x"),
		"relative/path",
	} {
		if err := s.Check(p); !errors.Is(err, diskguard.ErrProtected) {
			t.Errorf("%s: %v, want refused", p, err)
		}
	}
	for _, p := range []string{filepath.Join(root, "var/lib/log/pods/x/0.log.1"), filepath.Join(root, "tmp/junk")} {
		if err := s.Check(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}

// snapshot hashes every file and link under the protected paths.
func snapshot(t *testing.T, protected []string, skip string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, p := range protected {
		_ = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if skip != "" && (path == skip || strings.HasPrefix(path, skip+"/")) {
				return filepath.SkipDir
			}
			switch {
			case d.Type()&fs.ModeSymlink != 0:
				l, _ := os.Readlink(path)
				out[path] = "link:" + l
			case d.Type().IsRegular():
				b, _ := os.ReadFile(path)
				fi, _ := d.Info()
				s := sha256.Sum256(b)
				out[path] = hex.EncodeToString(s[:]) + fmt.Sprintf(":%v", fi.ModTime().UnixNano())
			case d.IsDir():
				out[path] = "dir"
			}
			return nil
		})
	}
	return out
}

// tryEverything is a step that asks the safety list to remove every
// protected path and everything under it.
type tryEverything struct{ protected []string }

func (tryEverything) Category() string { return "adversary" }
func (s tryEverything) Clean(_ context.Context, env diskguard.Env) (diskguard.Result, error) {
	for _, p := range s.protected {
		_ = filepath.WalkDir(p, func(path string, _ fs.DirEntry, err error) error {
			if err == nil {
				if _, rerr := env.Safety.Remove(path); !errors.Is(rerr, diskguard.ErrProtected) {
					return fmt.Errorf("%s: %v", path, rerr)
				}
			}
			return nil
		})
	}
	return diskguard.Result{}, nil
}

// The cleanup, every step at once with junk everywhere it may look, plus
// a step that tries to remove every protected path, leaves each protected
// path byte for byte as it was. Only the OS audit archive's export
// directory, on the backup volume, may gain files.
func TestCleanupLeavesProtectedPathsIdentical(t *testing.T) {
	root := t.TempDir()
	old := time.Now().Add(-30 * 24 * time.Hour)
	protected := under(root, diskguard.BoxProtected)
	for i, p := range protected {
		switch filepath.Base(p) {
		case "box-name", "machine-id":
			write(t, p, 32, old)
			continue
		}
		// An old file, a rotated-looking log, a .tmp and a .bin in each,
		// so a step that strayed would find something to take.
		write(t, filepath.Join(p, "data", fmt.Sprintf("file-%d", i)), 4096, old)
		write(t, filepath.Join(p, "pods", "x", "0.log.20260101-000000.gz"), 4096, old)
		write(t, filepath.Join(p, "upload.tmp"), 128, old)
		write(t, filepath.Join(p, "up-old.bin"), 128, old)
		mustNoErr(t, os.Symlink(filepath.Join(p, "data"), filepath.Join(p, "link")))
	}
	for _, s := range []string{"a", "b"} {
		write(t, filepath.Join(root, "var/lib/sneakers/product", s, "images", strings.Repeat(s, 64)+".tar"), 64, old)
	}
	logs := filepath.Join(root, "var/lib/log")
	uploads := filepath.Join(root, "var/lib/sneakers/osadmin-api/uploads")
	stage := filepath.Join(root, "var/lib/sneakers/image-stage")
	tmp := filepath.Join(root, "tmp")
	for i := range 5 {
		write(t, filepath.Join(logs, "pods", "ns_pod_uid", "c", fmt.Sprintf("0.log.2026010%d-000000.gz", i)), 8192, old.Add(time.Duration(i)*time.Hour))
	}
	write(t, filepath.Join(logs, "pods", "ns_pod_uid", "c", "0.log"), 8192, time.Time{})
	mustNoErr(t, os.Symlink(filepath.Join(root, "var/lib/sneakers-data/data"), filepath.Join(logs, "containers-data")))
	write(t, filepath.Join(uploads, "up-1.bin"), 4096, old)
	write(t, filepath.Join(uploads, "up-1.json"), 32, old)
	write(t, filepath.Join(uploads, "up-2.tmp"), 4096, old)
	write(t, filepath.Join(stage, "1.2.3", "root.img"), 4096, old)
	mustNoErr(t, os.Chtimes(filepath.Join(stage, "1.2.3"), old, old))
	write(t, filepath.Join(tmp, "old"), 4096, old)
	mustNoErr(t, os.Symlink(filepath.Join(root, "var/lib/sneakers/backup"), filepath.Join(tmp, "backup-link")))

	auditDir := filepath.Join(root, "var/lib/sneakers/os-audit")
	clk := &clock{t: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
	audit, err := osaudit.Open(auditDir, osaudit.Options{Now: clk.now})
	mustNoErr(t, err)
	for i := range 5 {
		mustNoErr(t, audit.Append(osaudit.Entry{Actor: "alice", Action: fmt.Sprintf("a%d", i)}))
		clk.t = clk.t.Add(24 * time.Hour)
	}
	export := filepath.Join(root, "var/lib/sneakers/backup/os-audit-archive")

	before := snapshot(t, protected, export)
	safety := diskguard.Safety{Allowed: []string{logs, uploads, stage, tmp}, Protected: protected}
	var rmArgs []string
	images := diskguard.Images{
		K0s: filepath.Join(root, "var/lib/sneakers/product/a/images"), Containerd: "/run/k0s/containerd.sock",
		Slots: []string{filepath.Join(root, "var/lib/sneakers/product/a"), filepath.Join(root, "var/lib/sneakers/product/b")},
		Run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			switch strings.Join(args[5:], " ") {
			case "images list":
				return []byte("REF TYPE DIGEST SIZE PLATFORMS LABELS\n" +
					"r/a:1 m sha256:" + strings.Repeat("a", 64) + " 1.0 MiB linux/amd64 -\n" +
					"r/b:1 m sha256:" + strings.Repeat("b", 64) + " 1.0 MiB linux/amd64 -\n" +
					"r/old:1 m sha256:" + strings.Repeat("c", 64) + " 1.0 MiB linux/amd64 -\n"), nil
			case "containers list":
				return []byte("CONTAINER IMAGE RUNTIME\n"), nil
			}
			rmArgs = append(rmArgs, args[5:]...)
			return nil, nil
		},
	}
	c := &diskguard.Cleaner{
		Safety: safety, Audit: audit,
		Statfs: func(string) (diskguard.Usage, error) {
			return diskguard.Usage{Total: 1 << 40, Used: 1 << 30, Avail: 1 << 30}, nil
		},
		Steps: []diskguard.Step{
			diskguard.PodLogs{Dir: logs, Cap: 1},
			&diskguard.AuditLog{Log: audit, Options: func(diskguard.Usage) osaudit.ArchiveOptions {
				return osaudit.ArchiveOptions{MaxBytes: 1, Grace: 0, ExportDir: export}
			}},
			images,
			diskguard.Updates{Uploads: uploads, StageDir: stage, Retention: 24 * time.Hour},
			diskguard.Tmp{Dir: tmp, Age: time.Hour},
			diskguard.WAL{Watches: func() []diskguard.Watch {
				return []diskguard.Watch{{Name: "db", Path: filepath.Join(root, "var/lib/sneakers-data/data"), WAL: ".", WALWarn: 1}}
			}},
			tryEverything{protected: protected},
		},
		StatePath: root,
	}
	run := c.Run(context.Background(), diskguard.TriggerAdmin, "alice")
	for _, cr := range run.Categories {
		if cr.Error != "" {
			t.Errorf("%s: %s", cr.Category, cr.Error)
		}
	}
	after := snapshot(t, protected, export)
	for p, h := range before {
		if after[p] != h {
			t.Errorf("%s changed: %q, was %q", p, after[p], h)
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			t.Errorf("%s appeared", p)
		}
	}

	// What it may take went.
	for _, p := range []string{filepath.Join(uploads, "up-1.bin"), filepath.Join(uploads, "up-2.tmp"), filepath.Join(stage, "1.2.3"), filepath.Join(tmp, "old"), filepath.Join(logs, "pods", "ns_pod_uid", "c", "0.log.20260100-000000.gz")} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s is still there", p)
		}
	}
	for _, p := range []string{filepath.Join(logs, "pods", "ns_pod_uid", "c", "0.log"), filepath.Join(logs, "containers-data"), filepath.Join(tmp, "backup-link")} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s: %v (a live log or a link isn't taken)", p, err)
		}
	}
	if strings.Join(rmArgs, " ") != "images rm --sync r/old:1" {
		t.Errorf("images removed: %q", rmArgs)
	}
	mustNoErr(t, audit.Verify())
	e, err := audit.Entries()
	mustNoErr(t, err)
	last := e[len(e)-1]
	if last.Action != diskguard.ActionCleanup || last.Actor != "alice" || last.Detail["freed.pod-logs"] == "0" || last.Detail["freed.updates"] == "0" || last.Detail["note.wal"] == "" {
		t.Fatalf("the run's audit entry: %+v", last)
	}
}
