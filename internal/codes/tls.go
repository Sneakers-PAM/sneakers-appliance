// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package codes

import apperr "github.com/Bugs5382/go-apperr"

// The certificate store codes (spec 3, Section 2.7.1): 38xx.
const (
	TLSInvalid             = 3801
	TLSFormat              = 3802
	TLSKeyMismatch         = 3803
	TLSKeyType             = 3804
	TLSChain               = 3805
	TLSNames               = 3806
	TLSValidity            = 3807
	TLSUsage               = 3808
	TLSUnknown             = 3809
	TLSInUse               = 3810
	TLSLimit               = 3811
	TLSEndpointUnavailable = 3812
	TLSNotServed           = 3813
	TLSACMEUnavailable     = 3814
)

var tlsEntries = []apperr.Entry{
	{Code: TLSInvalid, Symbol: "TLS_INVALID", Title: "tls", Cause: "a field of the request fails validation (the error names it)"},
	{Code: TLSFormat, Symbol: "TLS_FORMAT", Title: "tls", Cause: "a certificate, key or PKCS#12 file doesn't parse, is encrypted, or the PKCS#12 password is wrong"},
	{Code: TLSKeyMismatch, Symbol: "TLS_KEY_MISMATCH", Title: "tls", Cause: "the certificate isn't for the private key given, or for the CSR's key"},
	{Code: TLSKeyType, Symbol: "TLS_KEY_TYPE", Title: "tls", Cause: "the key isn't RSA of 3072 bits or more, or ECDSA P-256 or P-384"},
	{Code: TLSChain, Symbol: "TLS_CHAIN", Title: "tls", Cause: "the chain doesn't build to a root (the error names the missing issuer) or a certificate in it is invalid"},
	{Code: TLSNames, Symbol: "TLS_NAMES", Title: "tls", Cause: "the certificate's SANs cover none of the box's management names and addresses, or of the endpoint's"},
	{Code: TLSValidity, Symbol: "TLS_VALIDITY", Title: "tls", Cause: "the certificate has expired or isn't valid yet"},
	{Code: TLSUsage, Symbol: "TLS_USAGE", Title: "tls", Cause: "the certificate is a CA certificate or isn't for TLS servers"},
	{Code: TLSUnknown, Symbol: "TLS_UNKNOWN", Title: "tls", Cause: "no certificate, CSR or endpoint has that id"},
	{Code: TLSInUse, Symbol: "TLS_IN_USE", Title: "tls", Cause: "the certificate is in use by an endpoint, or is the box's self-signed one"},
	{Code: TLSLimit, Symbol: "TLS_LIMIT", Title: "tls", Cause: "the store already holds 32 certificates or 8 pending CSRs"},
	{Code: TLSEndpointUnavailable, Symbol: "TLS_ENDPOINT_UNAVAILABLE", Title: "tls", Cause: "the endpoint isn't on this box yet (the product endpoint needs the product installed)"},
	{Code: TLSNotServed, Symbol: "TLS_NOT_SERVED", Title: "tls", Cause: "the new certificate wasn't served within 15 seconds, so the previous one was put back"},
	{Code: TLSACMEUnavailable, Symbol: "TLS_ACME_UNAVAILABLE", Title: "tls", Cause: "ACME through cert-manager isn't available yet; it comes with the product bundle"},
}

func init() { Entries = append(Entries, tlsEntries...) }
