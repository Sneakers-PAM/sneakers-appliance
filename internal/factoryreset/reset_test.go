// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package factoryreset_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	diskfs "github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/partition/gpt"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/disk"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/factoryreset"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/luks"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/phase"
)

const diskSize = 100 * disk.GiB

var ctx = context.Background()

// The fake LUKS2 header the fixture writes: both header magics and a token
// that stands for a TPM-sealed copy of the state key.
var (
	luksMagic   = []byte{'L', 'U', 'K', 'S', 0xba, 0xbe}
	luksMagic2  = []byte{'S', 'K', 'U', 'L', 0xba, 0xbe}
	sealedToken = []byte(`{"type":"systemd-tpm2","tpm2-blob":"c2VhbGVk"}`)
)

// setUpImage writes a sparse disk image laid out as a box after first boot:
// the installed partitions, then first boot's (the key file only in
// key-file mode), each LUKS volume carrying a header and a sealed token.
func setUpImage(t *testing.T, keyfile bool) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "disk.raw")
	d, err := diskfs.Create(p, diskSize, diskfs.SectorSize512)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := disk.FirstBootPlan(diskSize, disk.InstalledBytes("amd64"), "amd64", keyfile)
	if err != nil {
		t.Fatal(err)
	}
	all := append(disk.Installed(), plan...)
	var parts []*gpt.Partition
	for _, q := range all {
		parts = append(parts, gptPart(q))
	}
	if err := d.Partition(&gpt.Table{Partitions: parts, LogicalSectorSize: disk.SectorSize, PhysicalSectorSize: disk.SectorSize, ProtectiveMBR: true}); err != nil {
		t.Fatal(err)
	}
	_ = d.Close()
	for _, q := range plan {
		writeAt(t, p, q.Start, luksMagic)
		writeAt(t, p, q.Start+4096, sealedToken)
		writeAt(t, p, q.Start+16*1024, luksMagic2)
		writeAt(t, p, q.Start+q.Size-disk.MiB, []byte("trailing signature"))
	}
	return p
}

func gptPart(q disk.Partition) *gpt.Partition {
	return &gpt.Partition{
		Index: q.Number, Start: uint64(q.Start / disk.SectorSize), End: uint64((q.Start+q.Size)/disk.SectorSize - 1), // #nosec G115 -- the fixed test layout
		Size: uint64(q.Size), Type: gpt.Type(q.Type), Name: q.Label, // #nosec G115 -- as above
	}
}

func writeAt(t *testing.T, p string, off int64, b []byte) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_WRONLY, 0) // #nosec G304 -- the test's image
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteAt(b, off); err != nil {
		t.Fatal(err)
	}
}

func readAt(t *testing.T, p string, off, n int64) []byte {
	t.Helper()
	f, err := os.Open(p) // #nosec G304 -- the test's image
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	b := make([]byte, n)
	if _, err := f.ReadAt(b, off); err != nil {
		t.Fatal(err)
	}
	return b
}

type fixture struct {
	img     string
	esp     string
	stopped int
	deps    factoryreset.Deps
}

func newFixture(t *testing.T, keyfile bool) *fixture {
	t.Helper()
	f := &fixture{img: setUpImage(t, keyfile), esp: t.TempDir()}
	f.deps = factoryreset.Deps{
		Store: factoryreset.FileStore{Dir: f.esp},
		Disk:  &factoryreset.GPTDisk{Path: f.img},
		Stop:  func(context.Context) error { f.stopped++; return nil },
		Now:   func() time.Time { return time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC) },
	}
	return f
}

func request() factoryreset.Record {
	return factoryreset.Record{ID: "R-ABC123", StartedBy: "alice", Approvals: []string{"alice", "bob"}}
}

func labels(t *testing.T, img string) []string {
	t.Helper()
	parts, err := (&factoryreset.GPTDisk{Path: img}).Partitions()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range parts {
		out = append(out, p.Label)
	}
	return out
}

func TestResetRemovesTheVolumesAndTheirKeys(t *testing.T) {
	for _, keyfile := range []bool{false, true} {
		f := newFixture(t, keyfile)
		plan, _ := disk.FirstBootPlan(diskSize, disk.InstalledBytes("amd64"), "amd64", keyfile)
		rec, err := factoryreset.Begin(f.deps, request())
		if err != nil {
			t.Fatal(err)
		}
		if rec.Step != factoryreset.StepBegun || len(rec.Regions) != len(plan) {
			t.Fatalf("begun record %+v", rec)
		}
		rec, err = factoryreset.Run(ctx, f.deps)
		if err != nil {
			t.Fatal(err)
		}
		if rec.Step != factoryreset.StepDone || rec.Pending() || f.stopped != 1 {
			t.Fatalf("record %+v, stopped %d", rec, f.stopped)
		}
		if got := labels(t, f.img); !slices.Equal(got, []string{disk.LabelESP, disk.LabelRootA, disk.LabelRootB}) {
			t.Fatalf("partitions left: %v", got)
		}
		for _, q := range plan {
			head := readAt(t, f.img, q.Start, min(q.Size, 16*disk.MiB))
			if bytes.Contains(head, luksMagic) || bytes.Contains(head, luksMagic2) || bytes.Contains(head, sealedToken) {
				t.Fatalf("%s still holds a LUKS header or a sealed token", q.Label)
			}
			if bytes.Contains(readAt(t, f.img, q.Start+q.Size-disk.MiB, disk.MiB), []byte("trailing signature")) {
				t.Fatalf("%s keeps its trailing signature", q.Label)
			}
		}
		got, ok, err := f.deps.Store.Read()
		if err != nil || !ok || got.Step != factoryreset.StepDone || got.StartedBy != "alice" || got.Finished.IsZero() {
			t.Fatalf("reset.json %+v %v %v", got, ok, err)
		}
	}
}

// The CryptOS-PKI lesson: a reset that leaves a LUKS header behind makes a
// node that can neither open nor re-format its volume. After this reset,
// first boot must find the free space it plans into and lay the volumes
// out again, and a second reset must work on that new layout.
func TestFirstBootAcceptsTheDiskAfterAReset(t *testing.T) {
	f := newFixture(t, false)
	for round := range 2 {
		if _, err := factoryreset.Begin(f.deps, request()); err != nil {
			t.Fatal(err)
		}
		if _, err := factoryreset.Run(ctx, f.deps); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		rec, _, _ := f.deps.Store.Read()
		if p := phase.Decide(phase.Facts{ResetPending: rec.Pending()}); p != phase.Firstboot {
			t.Fatalf("round %d: the boot after the reset is %s", round, p)
		}
		parts, err := (&factoryreset.GPTDisk{Path: f.img}).Partitions()
		if err != nil {
			t.Fatal(err)
		}
		plan, err := disk.FirstBootPlan(diskSize, disk.InstalledBytes("amd64"), "amd64", false)
		if err != nil {
			t.Fatal(err)
		}
		for _, q := range plan {
			for _, p := range parts {
				if q.Number == p.Number || q.Start < p.Start+p.Size && p.Start < q.Start+q.Size {
					t.Fatalf("round %d: first boot's %s collides with the left-over %s", round, q.Label, p.Label)
				}
			}
		}
		// First boot creates its partitions again in both GPT copies.
		d, err := diskfs.Open(f.img, diskfs.WithOpenMode(diskfs.ReadWrite))
		if err != nil {
			t.Fatal(err)
		}
		tbl, err := d.GetPartitionTable()
		if err != nil {
			t.Fatal(err)
		}
		g := tbl.(*gpt.Table)
		for _, q := range plan {
			g.Partitions = append(g.Partitions, gptPart(q))
			writeAt(t, f.img, q.Start, luksMagic)
		}
		if err := d.Partition(g); err != nil {
			t.Fatalf("round %d: first boot can't write its partitions: %v", round, err)
		}
		_ = d.Close()
		if got := labels(t, f.img); len(got) != 5 {
			t.Fatalf("round %d: after first boot %v", round, got)
		}
	}
}

func TestARealLUKSHeaderIsGone(t *testing.T) {
	if _, err := exec.LookPath("cryptsetup"); err != nil {
		if os.Getenv("SNEAKERS_REQUIRE_TOOLS") != "" {
			t.Fatal("cryptsetup isn't installed and SNEAKERS_REQUIRE_TOOLS is set")
		}
		t.Skip("cryptsetup isn't installed; CI installs it")
	}
	f := newFixture(t, false)
	vol := filepath.Join(t.TempDir(), "vol")
	if err := os.WriteFile(vol, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(vol, 32*disk.MiB); err != nil {
		t.Fatal(err)
	}
	dev := &luks.Device{Path: vol, Runner: &luks.ExecRunner{}, PBKDFArgs: []string{"--pbkdf-memory", "32768", "--pbkdf-parallel", "1", "--iter-time", "50"}}
	if err := dev.Format(ctx, bytes.Repeat([]byte{7}, 32)); err != nil {
		t.Fatal(err)
	}
	header, err := os.ReadFile(vol) // #nosec G304 -- the test's volume
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := disk.FirstBootPlan(diskSize, disk.InstalledBytes("amd64"), "amd64", false)
	state := plan[0]
	writeAt(t, f.img, state.Start, header[:16*disk.MiB])
	if _, err := factoryreset.Begin(f.deps, request()); err != nil {
		t.Fatal(err)
	}
	if _, err := factoryreset.Run(ctx, f.deps); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vol, readAt(t, f.img, state.Start, 32*disk.MiB), 0o600); err != nil {
		t.Fatal(err)
	}
	if dev.IsLUKS(ctx) {
		t.Fatal("cryptsetup still finds a LUKS header where the state volume was")
	}
}

// cutDisk and cutStore lose power after a number of writes: the write that
// hits the cut and everything after it fail, as on a box that went dark.
type power struct{ left int }

func (p *power) spend() error {
	if p.left == 0 {
		return errCut
	}
	p.left--
	return nil
}

var errCut = errors.New("power cut")

type cutDisk struct {
	factoryreset.Disk
	p *power
}

func (d cutDisk) WriteAt(b []byte, off int64) (int, error) {
	if err := d.p.spend(); err != nil {
		// Half the write lands, the way a torn write would.
		_, _ = d.Disk.WriteAt(b[:len(b)/2], off)
		return 0, err
	}
	return d.Disk.WriteAt(b, off)
}

func (d cutDisk) Delete(n []int) error {
	if err := d.p.spend(); err != nil {
		return err
	}
	return d.Disk.Delete(n)
}

type cutStore struct {
	factoryreset.RecordStore
	p *power
}

func (s cutStore) Write(r factoryreset.Record) error {
	if err := s.p.spend(); err != nil {
		return err
	}
	return s.RecordStore.Write(r)
}

func TestAPowerCutAtAnyStepFinishesOnTheNextBoot(t *testing.T) {
	for cut := 0; ; cut++ {
		f := newFixture(t, true)
		if _, err := factoryreset.Begin(f.deps, request()); err != nil {
			t.Fatal(err)
		}
		p := &power{left: cut}
		live := f.deps
		live.Disk, live.Store = cutDisk{Disk: f.deps.Disk, p: p}, cutStore{RecordStore: f.deps.Store, p: p}
		_, err := factoryreset.Run(ctx, live)
		if err == nil {
			if cut < 4 {
				t.Fatalf("the reset finished in only %d writes", cut)
			}
			return
		}
		// The next boot: the record says the reset isn't finished, so the
		// box can't boot normally, and the resume finishes it.
		rec, ok, rerr := f.deps.Store.Read()
		if rerr != nil || !ok || !rec.Pending() {
			t.Fatalf("cut %d: after the cut the record is %+v %v %v", cut, rec, ok, rerr)
		}
		if got := phase.Decide(phase.Facts{ResetPending: true, SetupDone: true}); got != phase.Reset {
			t.Fatalf("cut %d: a pending reset boots into %s", cut, got)
		}
		boot := f.deps
		boot.Stop = nil
		rec, err = factoryreset.Run(ctx, boot)
		if err != nil {
			t.Fatalf("cut %d: the resume failed: %v", cut, err)
		}
		if rec.Step != factoryreset.StepDone || rec.Attempts < 1 {
			t.Fatalf("cut %d: resumed record %+v", cut, rec)
		}
		if got := labels(t, f.img); len(got) != 3 {
			t.Fatalf("cut %d: partitions left %v", cut, got)
		}
	}
}

func TestBeginWritesNothingToTheDiskWhenTheRecordCantBeWritten(t *testing.T) {
	f := newFixture(t, false)
	before := labels(t, f.img)
	d := f.deps
	d.Store = cutStore{RecordStore: f.deps.Store, p: &power{}}
	if _, err := factoryreset.Begin(d, request()); err == nil {
		t.Fatal("Begin went ahead without its record")
	}
	if got := labels(t, f.img); !slices.Equal(got, before) || f.stopped != 0 {
		t.Fatalf("the disk changed: %v", got)
	}
	if _, ok, _ := f.deps.Store.Read(); ok {
		t.Fatal("a record was left behind")
	}
}

// verifyDisk hides the deletion, so the check after it must fail.
type verifyDisk struct{ factoryreset.Disk }

func (verifyDisk) Delete([]int) error { return nil }

func TestAFailedCheckStopsAndKeepsTheResetPending(t *testing.T) {
	f := newFixture(t, false)
	if _, err := factoryreset.Begin(f.deps, request()); err != nil {
		t.Fatal(err)
	}
	d := f.deps
	d.Disk = verifyDisk{f.deps.Disk}
	_, err := factoryreset.Run(ctx, d)
	if !codes.Is(err, codes.ResetVerify) {
		t.Fatalf("got %v", err)
	}
	rec, _, _ := f.deps.Store.Read()
	if !rec.Pending() || rec.LastError == "" {
		t.Fatalf("record %+v", rec)
	}
}

func TestAStepFailureIsResetFailed(t *testing.T) {
	f := newFixture(t, false)
	if _, err := factoryreset.Begin(f.deps, request()); err != nil {
		t.Fatal(err)
	}
	d := f.deps
	d.Stop = func(context.Context) error { return errors.New("the state volume is busy") }
	if _, err := factoryreset.Run(ctx, d); !codes.Is(err, codes.ResetFailed) {
		t.Fatalf("got %v", err)
	}
	if got := labels(t, f.img); len(got) != 5 {
		t.Fatalf("a failed stop went on to delete: %v", got)
	}
}

func TestTheRecordSurvivesATornRename(t *testing.T) {
	esp := t.TempDir()
	s := factoryreset.FileStore{Dir: esp}
	if err := s.Write(factoryreset.Record{ID: "R-1", Step: factoryreset.StepWiped}); err != nil {
		t.Fatal(err)
	}
	// A cut between writing the new file and renaming it: the old name is
	// gone (FAT's rename isn't atomic), the new one is complete.
	if err := os.Rename(filepath.Join(esp, factoryreset.RecordName), filepath.Join(esp, factoryreset.RecordName+".new")); err != nil {
		t.Fatal(err)
	}
	rec, ok, err := s.Read()
	if err != nil || !ok || rec.Step != factoryreset.StepWiped {
		t.Fatalf("%+v %v %v", rec, ok, err)
	}
}

func TestNoRecordMeansNoReset(t *testing.T) {
	_, ok, err := factoryreset.FileStore{Dir: t.TempDir()}.Read()
	if ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
}
