// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package codes

import apperr "github.com/Bugs5382/go-apperr"

// The vault root key rotation codes: 393x.
const (
	RootRotationUnavailable = 3930
	RootRotationUnfinished  = 3931
	RootRotationNotVerified = 3932
)

var rootRotationEntries = []apperr.Entry{
	{Code: RootRotationUnavailable, Symbol: "ROOTKEY_UNAVAILABLE", Title: "root key", Cause: "the installed product can't rotate the vault root key (its bundle names no previous key), or the box can't reach the vault's status"},
	{Code: RootRotationUnfinished, Symbol: "ROOTKEY_UNFINISHED", Title: "root key", Cause: "a root key rotation is under way or stopped half way; finish it (rotate again) before anything that applies the product"},
	{Code: RootRotationNotVerified, Symbol: "ROOTKEY_NOT_VERIFIED", Title: "root key", Cause: "the vault didn't verify the move to the new root key in time, or reported it failed; both keys are kept and nothing was deleted"},
}

func init() { Entries = append(Entries, rootRotationEntries...) }
