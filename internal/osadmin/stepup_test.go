// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
)

// The methods that ask for no code: staging only writes the inactive slot,
// the certificate store's edits don't change what :8443 serves, setup's
// Finish comes minutes after the code was enrolled, and the policies and
// ending a session change nothing that boots or lets anyone in. The role
// checks stay.
var noCode = []string{
	"UpgradeService.StageUpdate",
	"UpgradeService.SetUpgradePolicy",
	"PowerService.EndSession",
	"BackupService.SetBackupPolicy",
	"TlsService.DeleteCertificate",
	"TlsService.SetAcme",
	"SetupService.Finish",
	"TlsService.UploadCertificate",
	"TlsService.ImportCertificate",
	"TlsService.GenerateCsr",
	"TlsService.CompleteCsr",
	"TlsService.DiscardCsr",
	"TlsService.RenewNow",
}

// The methods that keep a code: what boots, who can get in, the box's keys,
// power and network, and what :8443 serves.
var withCode = []string{
	"UpgradeService.ApplyUpdate",
	"UpgradeService.RevertUpdate",
	"AccessService.IssueSshKey",
	"AccessService.AddAdmin",
	"AccessService.RemoveAdmin",
	"AccessService.SetRole",
	"AccessService.ChangePassword",
	"AccessService.SetAccessPolicy",
	"PowerService.Reboot",
	"PowerService.Shutdown",
	"NetworkService.SetNetwork",
	"BackupService.Restore",
	"SetupService.AddRecoveryKey",
	"SetupService.RemoveRecoveryKey",
	"TlsService.SetAdminCertificate",
	"TlsService.AssignCertificate",
	"TlsService.RevertToSelfSigned",
}

func ruleFor(t *testing.T, name string) *osadminv1.Rule {
	t.Helper()
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName("sneakers.appliance.osadmin.v1." + name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	md, ok := d.(protoreflect.MethodDescriptor)
	if !ok {
		t.Fatalf("%s is not a method", name)
	}
	r := osadmin.RuleOf(md)
	if r == nil {
		t.Fatalf("%s has no rule", name)
	}
	return r
}

func TestOnlyTheCriticalStepsAskForACode(t *testing.T) {
	for _, m := range noCode {
		if r := ruleFor(t, m); r.GetStepUp() || r.GetCodeEachCall() {
			t.Errorf("%s asks for a code", m)
		}
		if r := ruleFor(t, m); r.GetRole() == osadminv1.Role_ROLE_UNSPECIFIED {
			t.Errorf("%s lost its role check", m)
		}
	}
	for _, m := range withCode {
		if r := ruleFor(t, m); !r.GetStepUp() && !r.GetCodeEachCall() {
			t.Errorf("%s no longer asks for a code", m)
		}
	}
}

func TestStageNeedsNoCodeButApplyDoes(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	b.clk.Advance(10 * time.Minute)
	id, _ := alice.upload(t, bin(t, b.sign, b.enc, full(release.ChannelProduction)))
	if err := stage(alice, id); err != nil {
		t.Fatalf("a stage outside the step-up window: %v", err)
	}
	_, err := alice.upgrade().ApplyUpdate(ctx, connect.NewRequest(&osadminv1.ApplyUpdateRequest{}))
	symbolIn(t, err, connect.CodeInvalidArgument, "ACCESS_CONFIRM")
	if b.init.activated != 0 {
		t.Fatal("an apply with no code activated")
	}
	if _, err := alice.upgrade().ApplyUpdate(ctx, connect.NewRequest(&osadminv1.ApplyUpdateRequest{TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
}

func TestFinishNeedsNoFreshCode(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	su := osadminv1connect.NewSetupServiceClient(alice.hc, b.ts.URL)
	if _, err := su.AddRecoveryKey(ctx, connect.NewRequest(&osadminv1.AddRecoveryKeyRequest{PublicKey: newKey(t).line})); err != nil {
		t.Fatal(err)
	}
	acknowledge(t, su)
	b.clk.Advance(6 * time.Minute)
	if _, err := su.Finish(ctx, connect.NewRequest(&osadminv1.FinishRequest{})); err != nil {
		t.Fatalf("finish outside the step-up window: %v", err)
	}
}
