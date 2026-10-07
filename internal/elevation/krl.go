// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package elevation

import (
	"encoding/binary"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"
)

// The OpenSSH key revocation list format (PROTOCOL.krl in OpenSSH).
const (
	krlMagic              = "SSHKRL\n\x00"
	krlFormatVersion      = 1
	krlSectionCerts       = 1
	krlSectionExplicitKey = 2
	krlSectionCertSerial  = 0x20
)

// MarshalKRL is an OpenSSH revocation list that revokes each serial of a
// certificate signed by ca, and each of keys (removed login keys, and with
// them any certificate for one). version is the list's own version number.
func MarshalKRL(ca ssh.PublicKey, serials []uint64, keys []ssh.PublicKey, version uint64, generated time.Time) []byte {
	b := []byte(krlMagic)
	b = binary.BigEndian.AppendUint32(b, krlFormatVersion)
	b = binary.BigEndian.AppendUint64(b, version)
	b = binary.BigEndian.AppendUint64(b, uint64(max(generated.Unix(), 0))) // #nosec G115 -- clamped
	b = binary.BigEndian.AppendUint64(b, 0)                                // flags
	b = appendString(b, nil)                                               // reserved
	b = appendString(b, []byte("sneakers-appliance removed login keys and elevation certificates"))
	b = appendCertSerials(b, ca, serials)
	if len(keys) == 0 {
		return b
	}
	var explicit []byte
	for _, k := range keys {
		explicit = appendString(explicit, k.Marshal())
	}
	b = append(b, krlSectionExplicitKey)
	return appendString(b, explicit)
}

func appendCertSerials(b []byte, ca ssh.PublicKey, serials []uint64) []byte {
	if len(serials) == 0 {
		return b
	}
	sorted := slices.Clone(serials)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)
	var list []byte
	for _, s := range sorted {
		list = binary.BigEndian.AppendUint64(list, s)
	}
	var certs []byte
	certs = appendString(certs, ca.Marshal())
	certs = appendString(certs, nil) // reserved
	certs = append(certs, krlSectionCertSerial)
	certs = appendString(certs, list)
	b = append(b, krlSectionCerts)
	return appendString(b, certs)
}

func appendString(b, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s))) // #nosec G115 -- small sections
	return append(b, s...)
}
