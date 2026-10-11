// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
)

// The closed shell's "<product> reset" runs osadmin's ResetProduct as the
// login's admin, with the code it read at the command checked against
// that admin's authenticator: an admin, the console and :8443 are
// refused, and every call is audited from the ssh surface.
func TestTheShellsResetRunsAsTheOwnerWithItsOwnCode(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	alice := b.shell("alice")
	_, err := alice.ResetProduct(ctx, connect.NewRequest(&accessv1.ResetProductRequest{TotpCode: "000000", Confirm: "sneakers"}))
	symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_CREDENTIALS")
	if e := lastEntry(t, b.log, "product.reset"); e.Actor != "alice" || e.Outcome != "refused" || e.Detail["surface"] != "ssh" || e.KeyFP != b.keys["alice"].fp {
		t.Fatalf("%+v", e)
	}
	// With the right code it reaches the reset, which this box doesn't
	// have.
	_, err = alice.ResetProduct(ctx, connect.NewRequest(&accessv1.ResetProductRequest{TotpCode: b.code("alice"), Confirm: "sneakers"}))
	symbolIn(t, err, connect.CodeUnimplemented, "Not available")

	_, err = b.shell("bob").ResetProduct(ctx, connect.NewRequest(&accessv1.ResetProductRequest{TotpCode: b.code("bob"), Confirm: "sneakers"}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")

	hc, url := b.console()
	_, err = accessv1connect.NewAccessServiceClient(hc, url).ResetProduct(ctx, connect.NewRequest(&accessv1.ResetProductRequest{Confirm: "sneakers"}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	if e := lastEntry(t, b.log, "product.reset"); e.Actor != "console" || e.Outcome != "refused" {
		t.Fatalf("%+v", e)
	}

	hc, url = b.osadmin()
	_, err = osadminv1connect.NewProductServiceClient(hc, url).ResetProduct(ctx, connect.NewRequest(&osadminv1.ResetProductRequest{TotpCode: b.code("alice"), Confirm: "sneakers"}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
}
