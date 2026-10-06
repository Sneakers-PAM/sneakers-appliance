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

// The boot codes.
const (
	RootNotFound = 2001
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
