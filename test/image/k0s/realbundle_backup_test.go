// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

package k0s_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/test/image/harness"
)

// TestTheRealBundleRestoresABackup is a backup and restore on a real box: the
// product under test cuts a set while it runs, takes a write the set can't
// hold, restores the set with the owner's code, and comes back at the restore
// point with every earlier row, through a power loss too. The restore is the
// closed shell's, as an owner runs it.
func TestTheRealBundleRestoresABackup(t *testing.T) {
	e := needReal(t)
	image := os.Getenv("SNEAKERS_REAL_NEW_IMAGE")
	if image == "" {
		t.Skip("SNEAKERS_REAL_NEW_IMAGE names the base under test")
	}
	harness.Need(t, []string{"ssh"}, e.next, image)
	b := newRealBoxFrom(t, e, image, e.newVersion, 0)
	v := productVersion(e.next)

	b.apply(e.next, "UPDATE_TARGET_PRODUCT")
	base := b.mustRun(v, "the install of "+v, realRows{}, true, false).rows
	if p := canaryProblems(base); len(p) > 0 {
		t.Fatalf("the rows weren't written: %v", p)
	}

	out, err := ssh(b.ctx, b.sshPort, b.alice, "sneakers", "backup", "create", "realci-before")
	if err != nil || !strings.Contains(out, "is made") {
		t.Fatalf("backup create: %v\n%s", err, out)
	}
	t.Logf("backup create: %s", strings.TrimSpace(out))
	b.vm.Expect(`realci: later present=t`, 5*time.Minute)

	start := time.Now()
	if out := answerOverSSH(b.ctx, t, b.sshPort, b.alice, "realci-before", "sneakers", "backup", "restore", "realci-before"); !strings.Contains(out, "has started") {
		t.Fatalf("backup restore:\n%s", out)
	}
	b.vm.Expect(`realci: later present=f restore=(settling|done)`, 30*time.Minute)
	b.mustRun(v, "the restore", base, true, false)
	t.Logf("the restore took %s", time.Since(start).Round(time.Second))

	b.powerLoss()
	b.mustRun(v, "after a power loss", base, true, false)
	if l := lastLine(b.vm.Console(), "realci: later present="); !strings.Contains(l, "present=f") {
		t.Fatalf("the later write came back: %q", l)
	}
}
