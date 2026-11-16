// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package codes

import apperr "github.com/Bugs5382/go-apperr"

// The product's email settings codes: 39xx.
const (
	EmailInvalid     = 3901
	EmailSend        = 3902
	EmailUntrusted   = 3903
	EmailPinMismatch = 3904
	EmailNotTested   = 3905
	EmailCodeWrong   = 3906
	EmailCodeExpired = 3907
)

var emailEntries = []apperr.Entry{
	{Code: EmailInvalid, Symbol: "EMAIL_INVALID", Title: "email", Cause: "an email setting fails validation (the error names it)"},
	{Code: EmailSend, Symbol: "EMAIL_SEND", Title: "email", Cause: "the test email didn't go out; the error gives the relay's answer or the connection's failure"},
	{Code: EmailUntrusted, Symbol: "EMAIL_UNTRUSTED", Title: "email", Cause: "the relay's certificate isn't trusted (or a pinned one is outside its validity dates); nothing was sent, and the refusal carries the certificate to check and pin"},
	{Code: EmailPinMismatch, Symbol: "EMAIL_PIN_MISMATCH", Title: "email", Cause: "the relay presented another certificate than the pinned one; nothing was sent, and the refusal carries both fingerprints"},
	{Code: EmailNotTested, Symbol: "EMAIL_NOT_TESTED", Title: "email", Cause: "the relay settings being saved haven't passed a test email: send the test, then type the code from it (no pass, an expired pass, or settings or a password that changed after the code was typed)"},
	{Code: EmailCodeWrong, Symbol: "EMAIL_CODE_WRONG", Title: "email", Cause: "the code typed isn't the one the test email carried; five wrong tries drop the code"},
	{Code: EmailCodeExpired, Symbol: "EMAIL_CODE_EXPIRED", Title: "email", Cause: "no code is waiting for these settings and password: it was never sent, is older than ten minutes, was used or dropped after five wrong tries, or belongs to other settings; send the test email again"},
}

func init() { Entries = append(Entries, emailEntries...) }
