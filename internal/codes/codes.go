// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package codes holds the appliance's error codes. A code rides the error
// chain (go-apperr); the symbol is the stable name the docs and the console
// use. 1xxx: the build kit and the verification chain it shares with
// Image.Stage. 2xxx: boot (switchroot and init).
package codes

import (
	"fmt"
	"strings"

	apperr "github.com/Bugs5382/go-apperr"
)

// The kit codes (spec 1, Section 4.2).
const (
	KitPinMissing       = 1001
	KitSigMissing       = 1002
	KitWrongSigner      = 1003
	KitChannel          = 1004
	KitKitTooOld        = 1005
	KitDigestMismatch   = 1006
	KitAuthenticode     = 1007
	KitVerityMismatch   = 1008
	KitBundleMismatch   = 1009
	KitImageUnsigned    = 1010
	KitToolMissing      = 1011
	KitManifestInvalid  = 1012
	KitSourceUnreadable = 1013
)

// The boot and init codes.
const (
	RootNotFound        = 2001
	ServiceTableInvalid = 2101
	ServiceUnknown      = 2102
	ServiceNotOnDemand  = 2103
	ServicePreStart     = 2104
	ServiceWaiting      = 2105
)

// The Secure Boot codes.
const (
	SBNoEfivarfs   = 2201
	SBNotSetupMode = 2202
	SBEnrolFailed  = 2203
)

// The upgrade codes.
const (
	UpgradeDowngrade     = 2501
	UpgradeUnpredictable = 2502
	UpgradeNoPrevious    = 2503
	UpgradeFormat        = 2504
	UpgradeSignature     = 2505
	UpgradeDecrypt       = 2506
	UpgradeChannel       = 2507
	UpgradePatchBase     = 2508
	UpgradeAirGapped     = 2509
	UpgradeUpload        = 2510
	UpgradeNotStaged     = 2511
	UpgradeElevated      = 2512
	UpgradeProductBase   = 2513
	UpgradeNoReboot      = 2514
	UpgradeBusy          = 2515
	UpgradeProductStart  = 2516
	// ProductValueUnavailable: an exposed product value can't be read yet.
	ProductValueUnavailable = 2517
	// ProductNotReady: the product is still coming up or rolling out.
	ProductNotReady = 2518
	// ProductReset: removing the product stopped before it finished.
	ProductReset = 2519
	// The internal mirror's TLS refusals sit apart from the run above, so
	// other upgrade codes can follow 2514.
	UpgradeMirrorUntrusted = 2520
	UpgradeMirrorPin       = 2521
	// The three update units' refusals (spec 7).
	UpgradeCompat      = 2530
	UpgradeEpoch       = 2531
	UpgradeWebLoad     = 2532
	UpgradePatchResult = 2533
	// ProductNotInstalled: there's no installed product to act on.
	ProductNotInstalled = 2534
)

// The key custody codes.
const (
	KeyCustodyNoTPM          = 2301
	KeyCustodyInvalid        = 2302
	KeyCustodyNotInitialized = 2303
	KeyCustodyLocked         = 2304
	KeyCustodyNotFound       = 2305
	KeyCustodyRecipients     = 2306
	KeyCustodyPhase          = 2307
)

// Entries describes every code, for the registry and the docs.
var Entries = []apperr.Entry{
	{Code: KitPinMissing, Symbol: "KIT_PIN_MISSING", Title: "kit", Cause: "this kit was built without one of its pins, or with a channel other than production or lab"},
	{Code: KitSigMissing, Symbol: "KIT_SIG_MISSING", Title: "verify", Cause: "the artifact or release.yaml has no signature"},
	{Code: KitWrongSigner, Symbol: "KIT_WRONG_SIGNER", Title: "verify", Cause: "signed, but not by the pinned key"},
	{Code: KitChannel, Symbol: "KIT_CHANNEL", Title: "verify", Cause: "the manifest's channel isn't the kit's"},
	{Code: KitKitTooOld, Symbol: "KIT_KIT_TOO_OLD", Title: "verify", Cause: "kitMin is above this kit's version"},
	{Code: KitDigestMismatch, Symbol: "KIT_DIGEST_MISMATCH", Title: "verify", Cause: "a layer's SHA-256 differs from appliance.yaml"},
	{Code: KitAuthenticode, Symbol: "KIT_AUTHENTICODE", Title: "verify", Cause: "the UKI or loader doesn't verify against the pinned db certificate"},
	{Code: KitVerityMismatch, Symbol: "KIT_VERITY_MISMATCH", Title: "verify", Cause: "the root image doesn't match the UKI's root hash"},
	{Code: KitBundleMismatch, Symbol: "KIT_BUNDLE_MISMATCH", Title: "verify", Cause: "the bundle and release.yaml differ, or k0s isn't the pinned binary"},
	{Code: KitImageUnsigned, Symbol: "KIT_IMAGE_UNSIGNED", Title: "verify", Cause: "a bundled image lacks a valid org signature"},
	{Code: KitToolMissing, Symbol: "KIT_TOOL_MISSING", Title: "kit", Cause: "a tool the format needs isn't available"},
	{Code: KitManifestInvalid, Symbol: "KIT_MANIFEST_INVALID", Title: "verify", Cause: "appliance.yaml doesn't parse or breaks a structural rule"},
	{Code: KitSourceUnreadable, Symbol: "KIT_SOURCE_UNREADABLE", Title: "verify", Cause: "the artifact can't be resolved or read"},
	{Code: RootNotFound, Symbol: "ROOT_NOT_FOUND", Title: "boot", Cause: "no root slot matches the signed root hash, and no install medium holds the root image"},
	{Code: ServiceTableInvalid, Symbol: "SERVICE_TABLE_INVALID", Title: "init", Cause: "a service table entry doesn't parse, names an unknown service, or loops through after:"},
	{Code: ServiceUnknown, Symbol: "SERVICE_UNKNOWN", Title: "init", Cause: "the service table has no service of that name"},
	{Code: ServiceNotOnDemand, Symbol: "SERVICE_NOT_ON_DEMAND", Title: "init", Cause: "only on-demand services are started and stopped through the Services API"},
	{Code: ServicePreStart, Symbol: "SERVICE_PRE_START", Title: "init", Cause: "the service's pre-start hook failed, so it wasn't started"},
	{Code: ServiceWaiting, Symbol: "SERVICE_WAITING", Title: "init", Cause: "the service waits for a start-when path that doesn't exist yet"},
	{Code: SBNoEfivarfs, Symbol: "SB_NO_EFIVARFS", Title: "secureboot", Cause: "efivarfs isn't mounted or can't be read, so the Secure Boot state is unknown"},
	{Code: SBNotSetupMode, Symbol: "SB_NOT_SETUP_MODE", Title: "secureboot", Cause: "the firmware isn't in Setup Mode, so the org keys can't be enrolled; nothing was written"},
	{Code: SBEnrolFailed, Symbol: "SB_ENROL_FAILED", Title: "secureboot", Cause: "writing a Secure Boot key variable failed or didn't read back"},
	{Code: KeyCustodyNoTPM, Symbol: "KEYCUSTODY_NO_TPM", Title: "keycustody", Cause: "TPM mode was chosen on a box without a TPM"},
	{Code: KeyCustodyInvalid, Symbol: "KEYCUSTODY_INVALID", Title: "keycustody", Cause: "an unknown mode or choice, a second Initialize, or a disk too small for first boot"},
	{Code: KeyCustodyNotInitialized, Symbol: "KEYCUSTODY_NOT_INITIALIZED", Title: "keycustody", Cause: "the state volume has no custody header yet"},
	{Code: UpgradeDowngrade, Symbol: "UPGRADE_DOWNGRADE", Title: "upgrade", Cause: "the release isn't newer than the running one"},
	{Code: UpgradeUnpredictable, Symbol: "UPGRADE_UNPREDICTABLE", Title: "upgrade", Cause: "the release's UKI isn't one whose PCR 11 the box can predict"},
	{Code: UpgradeNoPrevious, Symbol: "UPGRADE_NO_PREVIOUS", Title: "upgrade", Cause: "there's no previous release to roll back to"},
	{Code: UpgradeFormat, Symbol: "UPGRADE_FORMAT", Title: "upgrade", Cause: "the file isn't a sneakers-appliance update package, or its header breaks the format's rules"},
	{Code: UpgradeSignature, Symbol: "UPGRADE_SIGNATURE", Title: "upgrade", Cause: "the update package isn't signed by this box's release key, or it changed after it was signed"},
	{Code: UpgradeDecrypt, Symbol: "UPGRADE_DECRYPT", Title: "upgrade", Cause: "the update package doesn't decrypt with this box's update key"},
	{Code: UpgradeChannel, Symbol: "UPGRADE_CHANNEL", Title: "upgrade", Cause: "a lab package never installs on a production box, and a production package never on a lab box"},
	{Code: UpgradePatchBase, Symbol: "UPGRADE_PATCH_BASE", Title: "upgrade", Cause: "the patch is for another base version, root image or UKI than the ones this box runs"},
	{Code: UpgradeAirGapped, Symbol: "UPGRADE_AIR_GAPPED", Title: "upgrade", Cause: "no mirror is configured, so the box fetches nothing; upload the .bin instead"},
	{Code: UpgradeUpload, Symbol: "UPGRADE_UPLOAD", Title: "upgrade", Cause: "the upload or fetch is unknown, too large, or failed"},
	{Code: UpgradeNotStaged, Symbol: "UPGRADE_NOT_STAGED", Title: "upgrade", Cause: "no release is staged to apply"},
	{Code: UpgradeElevated, Symbol: "UPGRADE_ELEVATED", Title: "upgrade", Cause: "an elevated shell is open; it ends, or an owner terminates it or overrides it (which ends it), before an update applies or reverts"},
	{Code: UpgradeProductBase, Symbol: "UPGRADE_PRODUCT_BASE", Title: "upgrade", Cause: "the product bundle doesn't fit the base version this box runs, or a base release is outside the installed product's base range"},
	{Code: UpgradeNoReboot, Symbol: "UPGRADE_NO_REBOOT", Title: "upgrade", Cause: "an apply or revert was accepted, but the box didn't reboot within the bound"},
	{Code: UpgradeBusy, Symbol: "UPGRADE_BUSY", Title: "upgrade", Cause: "a file is already coming in or waiting, or a stage is under way; verify or cancel it first"},
	{Code: UpgradeProductStart, Symbol: "UPGRADE_PRODUCT_START", Title: "upgrade", Cause: "a product apply or revert restarted the product, but it wasn't ready within the bound: its workloads hadn't rolled out, its health check didn't answer, or 443 didn't answer with it"},
	{Code: ProductNotReady, Symbol: "PRODUCT_NOT_READY", Title: "upgrade", Cause: "the product is still coming up or rolling out after an install, an update, a revert or an import's restart; try again once it's ready"},
	{Code: ProductReset, Symbol: "PRODUCT_RESET", Title: "upgrade", Cause: "removing the product stopped before it finished: the product didn't stop, k0s didn't answer or its objects or data didn't go; the reason says which, and the reset run again finishes it"},
	{Code: ProductNotInstalled, Symbol: "PRODUCT_NOT_INSTALLED", Title: "upgrade", Cause: "no product is installed, so there's nothing to remove; install it from the Product card on Updates"},
	{Code: ProductValueUnavailable, Symbol: "PRODUCT_VALUE_UNAVAILABLE", Title: "upgrade", Cause: "the product exposes that value, but it can't be read yet: the product or k0s isn't up, or its Secret isn't there"},
	{Code: UpgradeMirrorUntrusted, Symbol: "UPGRADE_MIRROR_UNTRUSTED", Title: "upgrade", Cause: "the HTTPS mirror's certificate doesn't chain to the system roots or the update trust's CA, or doesn't name the mirror's host"},
	{Code: UpgradeMirrorPin, Symbol: "UPGRADE_MIRROR_PIN", Title: "upgrade", Cause: "the HTTPS mirror's certificate isn't the one the update trust pins"},
	{Code: UpgradeCompat, Symbol: "UPGRADE_COMPAT", Title: "upgrade", Cause: "an update unit doesn't fit the other units this box runs, such as a Base Web built for another Base OS"},
	{Code: UpgradeEpoch, Symbol: "UPGRADE_EPOCH", Title: "upgrade", Cause: "the update is for another signing-key epoch than this box's"},
	{Code: UpgradeWebLoad, Symbol: "UPGRADE_WEB_LOAD", Title: "upgrade", Cause: "a Base Web slot failed its load checks (signature, file hashes, or a file that isn't listed); the pages it would replace keep serving"},
	{Code: UpgradePatchResult, Symbol: "UPGRADE_PATCH_RESULT", Title: "upgrade", Cause: "a patch didn't rebuild the release byte for byte; nothing was staged"},
	{Code: KeyCustodyLocked, Symbol: "KEYCUSTODY_LOCKED", Title: "keycustody", Cause: "the state key can't be recovered: no sealed copy unseals, or the key file is missing"},
	{Code: KeyCustodyNotFound, Symbol: "KEYCUSTODY_NOT_FOUND", Title: "keycustody", Cause: "there's no sealed item of that name"},
	{Code: KeyCustodyRecipients, Symbol: "KEYCUSTODY_RECIPIENTS", Title: "keycustody", Cause: "the escrow takes one to three ssh-ed25519 or ssh-rsa recovery keys"},
	{Code: KeyCustodyPhase, Symbol: "KEYCUSTODY_PHASE", Title: "keycustody", Cause: "an escrow is imported only in firstboot, before any root secret is sealed"},
}

// Registry is the code table.
func Registry() (*apperr.Registry, error) { return apperr.NewRegistry(Entries) }

// New returns an error carrying code, with a plain sentence as its text.
func New(code int, format string, args ...any) error {
	return apperr.Coded(code, fmt.Errorf(format, args...))
}

// Wrap attaches code to err.
func Wrap(code int, err error) error { return apperr.Coded(code, err) }

// Of returns the code on err's chain.
func Of(err error) (int, bool) { return apperr.Code(err) }

// Is reports whether err carries code.
func Is(err error, code int) bool {
	c, ok := apperr.Code(err)
	return ok && c == code
}

// Symbol returns the stable name of code, or "" for an unknown code.
func Symbol(code int) string {
	for _, e := range Entries {
		if e.Code == code {
			return e.Symbol
		}
	}
	return ""
}

// Describe renders err for a person: "KIT_CHANNEL (1004): <sentence>".
func Describe(err error) string {
	code, ok := apperr.Code(err)
	if !ok {
		return err.Error()
	}
	sentence := strings.Replace(err.Error(), fmt.Sprintf("code %d: ", code), "", 1)
	return fmt.Sprintf("%s (%d): %s", Symbol(code), code, sentence)
}
