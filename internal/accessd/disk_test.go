// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd_test

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accounts"
)

// The closed shell's bundle goes to accessd as the login's admin, with the
// login's key and address for its audit entry.
func TestTheShellsSupportBundleRunsAsTheAdmin(t *testing.T) {
	b := newBox(t)
	hc, url := b.as(b.uids["bob"])
	req, err := http.NewRequest(http.MethodGet, url+accessapi.SupportBundlePath+"?form=full", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(accessapi.KeyHeader, b.keys["bob"].fp)
	req.Header.Set(accessapi.SourceHeader, "192.0.2.60")
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("with no bundle configured: %d", resp.StatusCode)
	}
	e := lastEntry(t, b.log, "support.bundle")
	if e.Actor != "bob" || e.Detail["surface"] != "ssh" || e.Detail["form"] != "full" || e.KeyFP != b.keys["bob"].fp || e.Source != "192.0.2.60" || e.Outcome != "refused" {
		t.Fatalf("%+v", e)
	}
}

// The route is the shell's and the console's: the :8443 side can't reach
// it, and a uid that's no admin's is refused.
func TestOnlyALoginGetsTheSupportBundleRoute(t *testing.T) {
	b := newBox(t)
	for _, uid := range []uint32{accounts.OsadminUID, accounts.EdgefallUID, 60000} {
		hc, url := b.as(uid)
		resp, err := hc.Get(url + accessapi.SupportBundlePath)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusServiceUnavailable {
			t.Fatalf("uid %d reached it: %d", uid, resp.StatusCode)
		}
	}
}

// The closed shell's disk cleanup runs osadmin's CleanUpDisk as the
// login's admin, under its role and its disk.cleanup audit entry, marked
// as an SSH call.
func TestTheShellsDiskCleanupRunsAsTheAdmin(t *testing.T) {
	b := newBox(t)
	_, err := b.shell("bob").CleanUpDisk(context.Background(), connect.NewRequest(&accessv1.CleanUpDiskRequest{}))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("with no disk guard: %v", err)
	}
	if e := lastEntry(t, b.log, "disk.cleanup"); e.Actor != "bob" || e.Detail["surface"] != "ssh" || e.KeyFP != b.keys["bob"].fp {
		t.Fatalf("%+v", e)
	}
}
