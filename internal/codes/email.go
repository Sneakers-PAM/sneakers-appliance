// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package codes

import apperr "github.com/Bugs5382/go-apperr"

// The product's email settings codes: 39xx.
const (
	EmailInvalid = 3901
	EmailSend    = 3902
)

var emailEntries = []apperr.Entry{
	{Code: EmailInvalid, Symbol: "EMAIL_INVALID", Title: "email", Cause: "an email setting fails validation (the error names it)"},
	{Code: EmailSend, Symbol: "EMAIL_SEND", Title: "email", Cause: "the test email didn't go out; the error gives the relay's answer or the connection's failure"},
}

func init() { Entries = append(Entries, emailEntries...) }
