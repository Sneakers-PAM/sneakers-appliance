// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package switchroot

import (
	"errors"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

var (
	hash = "00112233445566778899aabbccddeeff" + strings.Repeat("0", 32)
	cmd  = "sneakers.roothash=" + hash + " sneakers.hashoffset=4096 sneakers.version=0.1.0 quiet"
)

func TestFindRootByRootHash(t *testing.T) {
	parts := []Partition{
		{Device: "/dev/sda2", Label: LabelRootA, PartUUID: "ffffffff-ffff-ffff-ffff-ffffffffffff"},
		{Device: "/dev/sda3", Label: LabelRootB, PartUUID: "00112233-4455-6677-8899-AABBCCDDEEFF"},
	}
	r, err := FindRoot(cmd, parts)
	if err != nil || r.Label != LabelRootB || r.Install() {
		t.Fatalf("got %+v %v", r, err)
	}
	parts[0].PartUUID, parts[1].PartUUID = parts[1].PartUUID, parts[0].PartUUID
	if r, err := FindRoot(cmd, parts); err != nil || r.Label != LabelRootA {
		t.Fatalf("slot A: %+v %v", r, err)
	}
}

func TestFindRootRefusals(t *testing.T) {
	good := Partition{Device: "/dev/sda2", Label: LabelRootA, PartUUID: "00112233-4455-6677-8899-aabbccddeeff"}
	for name, c := range map[string]struct {
		cmd   string
		parts []Partition
	}{
		"no slot":           {cmd, []Partition{{Device: "/dev/sda2", Label: LabelRootA, PartUUID: "ffffffff-ffff-ffff-ffff-ffffffffffff"}}},
		"right uuid, other": {cmd, []Partition{{Device: "/dev/sda5", Label: "sneakers-state", PartUUID: good.PartUUID}}},
		"two matches":       {cmd, []Partition{good, {Device: "/dev/sdb2", Label: LabelRootB, PartUUID: good.PartUUID}}},
		"no root hash":      {"quiet", []Partition{good}},
	} {
		if _, err := FindRoot(c.cmd, c.parts); !codes.Is(err, codes.RootNotFound) {
			t.Errorf("%s: want ROOT_NOT_FOUND, got %v", name, err)
		}
	}
}

func TestFindRootOnTheInstallMedium(t *testing.T) {
	r, err := FindRoot(cmd, []Partition{{Device: "/dev/sr0", VolumeLabel: InstallLabel}, {Device: "/dev/vda1", Label: "other"}})
	if err != nil || !r.Install() || r.Device != "/dev/sr0" || r.ImageFile != "root-0.1.0.img" {
		t.Fatalf("got %+v %v", r, err)
	}
}

// fakeSystem records what the shim does.
type fakeSystem struct {
	calls  []string
	parts  []Partition
	failOn string
}

func (f *fakeSystem) rec(s string) error {
	f.calls = append(f.calls, s)
	if f.failOn != "" && strings.HasPrefix(s, f.failOn) {
		return errors.New("boom")
	}
	return nil
}
func (f *fakeSystem) Mkdir(p string, _ uint32) error { return f.rec("mkdir " + p) }
func (f *fakeSystem) Mount(src, dst, fstype string, _ uintptr, _ string) error {
	return f.rec("mount " + src + " " + dst + " " + fstype)
}
func (f *fakeSystem) Unmount(p string, _ int) error { return f.rec("umount " + p) }
func (f *fakeSystem) ReadFile(string) ([]byte, error) {
	return []byte(cmd + "\n"), f.rec("read /proc/cmdline")
}
func (f *fakeSystem) Partitions() ([]Partition, error) { return f.parts, f.rec("partitions") }
func (f *fakeSystem) AttachLoop(p string) (string, error) {
	return "/dev/loop0", f.rec("loop " + p)
}
func (f *fakeSystem) Run(argv []string) error { return f.rec("run " + strings.Join(argv, " ")) }
func (f *fakeSystem) Chdir(d string) error    { return f.rec("chdir " + d) }
func (f *fakeSystem) Chroot(d string) error   { return f.rec("chroot " + d) }
func (f *fakeSystem) Logf(string, ...any)     {}
func (f *fakeSystem) Exec(p string, _, env []string) error {
	return f.rec("exec " + p + " " + strings.Join(env, " "))
}

func TestRunOpensTheSlotWithVerity(t *testing.T) {
	f := &fakeSystem{parts: []Partition{{Device: "/dev/vda3", Label: LabelRootB, PartUUID: "00112233-4455-6677-8899-aabbccddeeff"}}}
	err := Run(f, nil)
	if err == nil || !strings.Contains(err.Error(), "exec returned") {
		t.Fatalf("got %v", err)
	}
	got := strings.Join(f.calls, "\n")
	for _, want := range []string{
		"mount devtmpfs /dev devtmpfs",
		"run /usr/sbin/veritysetup open /dev/vda3 sneakers-root /dev/vda3 " + hash + " --hash-offset=4096 --panic-on-corruption",
		"mount /dev/mapper/sneakers-root /sysroot squashfs",
		"mount /dev /sysroot/dev ",
		"chroot .",
		"exec /sbin/init SNEAKERS_ROOT_SOURCE=sneakers-root-b",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Index(got, "veritysetup") > strings.Index(got, "/sysroot squashfs") {
		t.Error("the root must be opened with verity before it's mounted")
	}
}

func TestRunInstallModeUsesALoopDevice(t *testing.T) {
	f := &fakeSystem{parts: []Partition{{Device: "/dev/sr0", VolumeLabel: InstallLabel}}}
	_ = Run(f, nil)
	got := strings.Join(f.calls, "\n")
	for _, want := range []string{
		"mount /dev/sr0 /run/sneakers-install iso9660",
		"loop /run/sneakers-install/root-0.1.0.img",
		"run /usr/sbin/veritysetup open /dev/loop0 sneakers-root /dev/loop0 " + hash,
		"SNEAKERS_ROOT_SOURCE=install",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
}

func TestRunStopsWhenVerityFails(t *testing.T) {
	f := &fakeSystem{failOn: "run ", parts: []Partition{{Device: "/dev/vda2", Label: LabelRootA, PartUUID: "00112233-4455-6677-8899-aabbccddeeff"}}}
	if err := Run(f, nil); err == nil || !strings.Contains(err.Error(), "veritysetup") {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(strings.Join(f.calls, "\n"), "exec") {
		t.Fatal("must not switch into an unverified root")
	}
}

func TestRunRefusesAMissingRoot(t *testing.T) {
	if err := Run(&fakeSystem{}, nil); !codes.Is(err, codes.RootNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestPartDevice(t *testing.T) {
	for disk, want := range map[string]string{"sda": "/dev/sda2", "vda": "/dev/vda2", "nvme0n1": "/dev/nvme0n1p2", "mmcblk0": "/dev/mmcblk0p2"} {
		if got := partDevice(disk, 2); got != want {
			t.Errorf("%s: %s", disk, got)
		}
	}
}
