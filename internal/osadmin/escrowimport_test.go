// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
)

const escrowSecret = "decrypted-escrow-bytes-never-stored"

func importAs(b *box, l osadmin.Local, req *osadminv1.ImportEscrowRequest) (*osadminv1.ImportEscrowResponse, error) {
	h := b.srv.Handlers()
	var out *osadminv1.ImportEscrowResponse
	err := b.srv.RunLocalCall(context.Background(), l, osadminv1connect.SetupServiceImportEscrowProcedure, req, func(ctx context.Context) error {
		r, err := h.Setup.ImportEscrow(ctx, connect.NewRequest(req))
		if err == nil {
			out = r.Msg
		}
		return err
	})
	return out, err
}

// An owner over SSH hands init the decrypted escrow. The answer and the
// audit entry name what came over and what the box kept, and neither the
// state volume nor the audit log holds the escrow.
func TestAnOwnerImportsAnEscrowOverSSH(t *testing.T) {
	b := newBox(t, false)
	b.init.importRes = &initv1.ImportEscrowResponse{Imported: []string{"product-sneakers-totp-key", "product-sneakers-vault-root-key"}, Kept: []string{"root-key"}}
	out, err := importAs(b, b.ssh("alice"), &osadminv1.ImportEscrowRequest{Escrow: []byte(escrowSecret)})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.GetImported()) != 2 || len(out.GetKept()) != 1 {
		t.Fatalf("answer %v", out)
	}
	if len(b.init.imports) != 1 || string(b.init.imports[0]) != escrowSecret {
		t.Fatalf("init was given %q", b.init.imports)
	}
	e := lastEntry(t, b.log, "setup.escrow.import")
	if e.Outcome != "ok" || e.Detail["imported"] != "product-sneakers-totp-key,product-sneakers-vault-root-key" || e.Detail["kept"] != "root-key" {
		t.Fatalf("audited %+v", e)
	}
	if err := filepath.WalkDir(b.state, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if body, err := os.ReadFile(p); err == nil && bytes.Contains(body, []byte(escrowSecret)) { // #nosec G304 -- the test's temp dir
			t.Errorf("%s holds the escrow", p)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// init's refusal (not first boot, nothing new, a bad escrow) comes back as
// it is, audited as a failure with no escrow in the entry.
func TestAnEscrowImportInitRefusesIsAuditedWithoutTheEscrow(t *testing.T) {
	b := newBox(t, false)
	b.init.importErr = connect.NewError(connect.CodeFailedPrecondition, errors.New("KEYCUSTODY_PHASE (2307): an escrow is imported only in firstboot"))
	_, err := importAs(b, b.ssh("alice"), &osadminv1.ImportEscrowRequest{Escrow: []byte(escrowSecret)})
	symbolIn(t, err, connect.CodeFailedPrecondition, "KEYCUSTODY_PHASE")
	if e := lastEntry(t, b.log, "setup.escrow.import"); e.Outcome == "ok" || bytes.Contains([]byte(e.Target+e.Outcome), []byte(escrowSecret)) {
		t.Fatalf("audited %+v", e)
	}
}

// Only an owner, and only over SSH: an admin, or the :8443 API, is refused
// before init is asked.
func TestAnEscrowImportIsForOwnersOverSSH(t *testing.T) {
	b := newBox(t, true)
	b.init.importRes = &initv1.ImportEscrowResponse{Imported: []string{"x"}}
	_, err := importAs(b, b.ssh("bob"), &osadminv1.ImportEscrowRequest{Escrow: []byte(escrowSecret)})
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	bob := b.browser()
	bob.signIn("alice")
	_, err = osadminv1connect.NewSetupServiceClient(bob.hc, b.ts.URL).ImportEscrow(context.Background(), connect.NewRequest(&osadminv1.ImportEscrowRequest{Escrow: []byte(escrowSecret)}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	if len(b.init.imports) != 0 {
		t.Fatalf("init was asked: %d calls", len(b.init.imports))
	}
}
