// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
)

// The closed shell's updates command runs osadmin's GetUpgrades and
// SetUpgradePolicy as the login's admin: an owner sets the channel, which
// keeps the rest of the policy, and an admin may only look.
func TestTheShellsUpdatesCallsRunTheUpgradeServiceAsTheAdmin(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	alice, bob := b.shell("alice"), b.shell("bob")
	g, err := bob.GetUpdateChannel(ctx, connect.NewRequest(&accessv1.GetUpdateChannelRequest{}))
	if err != nil || g.Msg.GetPolicy().GetMode() != "automatic" {
		t.Fatalf("%v %v", g, err)
	}
	_, err = bob.SetUpdateChannel(ctx, connect.NewRequest(&accessv1.SetUpdateChannelRequest{ReleaseChannel: proto.String("rc")}))
	symbolIn(t, err, connect.CodeOf(err), "ACCESS_FORBIDDEN")
	if _, err := alice.SetUpdateChannel(ctx, connect.NewRequest(&accessv1.SetUpdateChannelRequest{ReleaseChannel: proto.String("rc")})); err != nil {
		t.Fatal(err)
	}
	g, err = alice.GetUpdateChannel(ctx, connect.NewRequest(&accessv1.GetUpdateChannelRequest{}))
	if err != nil || g.Msg.GetPolicy().GetReleaseChannel() != "rc" || g.Msg.GetPolicy().GetMode() != "automatic" || g.Msg.GetPolicy().GetWindowStart() != "02:00" {
		t.Fatalf("%v %v", g, err)
	}
	if e := lastEntry(t, b.log, "upgrade.policy.set"); e.Actor != "alice" || e.Detail["surface"] != "ssh" {
		t.Fatalf("%+v", e)
	}
	_, err = alice.SetUpdateChannel(ctx, connect.NewRequest(&accessv1.SetUpdateChannelRequest{ReleaseRepo: proto.String("example/throwaway")}))
	symbolIn(t, err, connect.CodeOf(err), "ACCESS_CONFIRM")
}
