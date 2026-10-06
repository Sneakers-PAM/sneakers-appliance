// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0
// Copyright The CryptOS Authors.

// Package tpm wraps github.com/google/go-tpm to provide:
//
//   - SRK provisioning under the Storage Hierarchy at persistent handle
//     0x81000001.
//   - Creation of ECDSA P-384 and RSA-3072/RSA-4096 CA signing keys bound
//     to the SRK; the private blob never leaves the TPM in the clear. An
//     RSA size the TPM does not implement is refused up front
//     (ErrKeyAlgorithmUnsupported), never substituted.
//   - A crypto.Signer implementation that routes through TPM2_Sign and
//     returns DER-encoded ECDSA signatures, or raw RSASSA-PKCS1-v1_5 /
//     RSASSA-PSS signatures chosen by the caller's crypto.SignerOpts, for
//     crypto/x509 to consume directly.
//   - Capability probing (ECC curves, and RSA key sizes via TPM2_TestParms)
//     so PID 1 can fail fast when P-384 is unavailable on the target TPM.
//
// go-tpm sits on the wire-format side of the project's stdlib-only-on-
// the-crypto-path rule, not the crypto side: it marshals TPM2 command
// structures and routes them to the TPM; the TPM does the math.
package tpm
