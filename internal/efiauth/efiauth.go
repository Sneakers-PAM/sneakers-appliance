// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package efiauth reads and verifies UEFI time-based authenticated variable
// payloads (EFI_VARIABLE_AUTHENTICATION_2 followed by the variable's data,
// the .auth files efitools' sign-efi-sig-list writes) and EFI signature
// lists.
//
// Verification binds the signature to the variable name, vendor GUID,
// attributes, timestamp and data, as the firmware does (UEFI 2.10, Section
// 8.2.2), and trusts only the certificate it's given.
package efiauth

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
	"unicode/utf16"

	"github.com/smallstep/pkcs7"
)

// Attributes of the Secure Boot key variables: non-volatile, boot service
// and runtime access, time-based authenticated writes.
const Attributes uint32 = 0x00000027

// GUIDs, in their on-disk (mixed-endian) byte order.
var (
	GlobalVariable = mustGUID("8be4df61-93ca-11d2-aa0d-00e098032b8c")
	ImageSecurity  = mustGUID("d719b2cb-3d3a-4596-a3bc-dad00e67656f")
	certPKCS7      = mustGUID("4aafd29d-68df-49ee-8aa9-347d375665a7")
	certX509       = mustGUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")
	certSHA256     = mustGUID("c1c41626-504c-4092-aca9-41f936934328")
)

// VendorFor returns the vendor GUID of a Secure Boot variable.
func VendorFor(name string) ([16]byte, error) {
	switch name {
	case "PK", "KEK":
		return GlobalVariable, nil
	case "db", "dbx":
		return ImageSecurity, nil
	}
	return [16]byte{}, fmt.Errorf("efiauth: %q isn't a Secure Boot key variable", name)
}

// ErrMalformed reports bytes that aren't an authenticated variable or a
// signature list.
var ErrMalformed = errors.New("efiauth: malformed")

// ErrSignature reports an authenticated variable that doesn't verify with the
// given certificate.
var ErrSignature = errors.New("efiauth: signature does not verify")

// Auth is a parsed .auth file.
type Auth struct {
	Timestamp [16]byte // EFI_TIME
	// SignedData is the PKCS#7 SignedData without its ContentInfo wrapper,
	// as the firmware receives it.
	SignedData []byte
	// Data is the variable's new value (an EFI signature list for the key
	// variables).
	Data []byte
}

// ParseAuth reads an EFI_VARIABLE_AUTHENTICATION_2 header and the data after
// it.
func ParseAuth(b []byte) (*Auth, error) {
	// EFI_TIME (16), then WIN_CERTIFICATE_UEFI_GUID: dwLength (4),
	// wRevision (2), wCertificateType (2), CertType GUID (16), CertData.
	const hdr = 16 + 4 + 2 + 2 + 16
	if len(b) < hdr {
		return nil, fmt.Errorf("%w: %d bytes is shorter than the header", ErrMalformed, len(b))
	}
	var a Auth
	copy(a.Timestamp[:], b[:16])
	length := binary.LittleEndian.Uint32(b[16:20])
	rev := binary.LittleEndian.Uint16(b[20:22])
	typ := binary.LittleEndian.Uint16(b[22:24])
	var ct [16]byte
	copy(ct[:], b[24:40])
	switch {
	case rev != 0x0200:
		return nil, fmt.Errorf("%w: WIN_CERTIFICATE revision %#x", ErrMalformed, rev)
	case typ != 0x0ef1:
		return nil, fmt.Errorf("%w: WIN_CERTIFICATE type %#x, want WIN_CERT_TYPE_EFI_GUID", ErrMalformed, typ)
	case ct != certPKCS7:
		return nil, fmt.Errorf("%w: the certificate type isn't PKCS#7", ErrMalformed)
	case int64(length) < 24 || 16+int64(length) > int64(len(b)):
		return nil, fmt.Errorf("%w: WIN_CERTIFICATE length %d", ErrMalformed, length)
	}
	end := 16 + int(length)
	a.SignedData = append([]byte(nil), b[40:end]...)
	a.Data = append([]byte(nil), b[end:]...)
	return &a, nil
}

// SignedBytes is what the signature covers: the variable name in UTF-16
// without its terminator, the vendor GUID, the attributes, the timestamp and
// the data.
func SignedBytes(name string, vendor [16]byte, attrs uint32, ts [16]byte, data []byte) []byte {
	var buf bytes.Buffer
	for _, u := range utf16.Encode([]rune(name)) {
		_ = binary.Write(&buf, binary.LittleEndian, u)
	}
	buf.Write(vendor[:])
	_ = binary.Write(&buf, binary.LittleEndian, attrs)
	buf.Write(ts[:])
	buf.Write(data)
	return buf.Bytes()
}

var oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

// Verify checks a's signature for the variable name with Attributes, trusting
// only signer.
func (a *Auth) Verify(name string, signer *x509.Certificate) error {
	vendor, err := VendorFor(name)
	if err != nil {
		return err
	}
	wrapped, err := wrapContentInfo(a.SignedData)
	if err != nil {
		return err
	}
	p7, err := pkcs7.Parse(wrapped)
	if err != nil {
		return fmt.Errorf("%w: PKCS#7: %v", ErrMalformed, err)
	}
	// Only the given certificate can verify: whatever the SignedData embeds
	// is ignored.
	p7.Certificates = []*x509.Certificate{signer}
	p7.Content = SignedBytes(name, vendor, Attributes, a.Timestamp, a.Data)
	if err := p7.VerifyWithChainAtTime(nil, time.Now()); err != nil {
		return fmt.Errorf("%w: %v", ErrSignature, err)
	}
	return nil
}

func wrapContentInfo(signedData []byte) ([]byte, error) {
	var raw asn1.RawValue
	if rest, err := asn1.Unmarshal(signedData, &raw); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("%w: SignedData isn't one DER value", ErrMalformed)
	}
	oid, err := asn1.Marshal(oidSignedData)
	if err != nil {
		return nil, err
	}
	explicit, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: signedData})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: append(oid, explicit...)})
}

// Entry is one entry of an EFI signature list.
type Entry struct {
	Type  string // "x509" or "sha256"
	Owner [16]byte
	Data  []byte
}

// ParseSignatureLists reads a concatenation of EFI_SIGNATURE_LISTs. Only
// X.509 and SHA-256 lists are accepted.
func ParseSignatureLists(b []byte) ([]Entry, error) {
	var out []Entry
	for off := 0; off < len(b); {
		if len(b)-off < 28 {
			return nil, fmt.Errorf("%w: %d trailing bytes", ErrMalformed, len(b)-off)
		}
		var typ [16]byte
		copy(typ[:], b[off:off+16])
		listSize := int(binary.LittleEndian.Uint32(b[off+16:]))
		headerSize := int(binary.LittleEndian.Uint32(b[off+20:]))
		sigSize := int(binary.LittleEndian.Uint32(b[off+24:]))
		if listSize < 28+headerSize || off+listSize > len(b) || sigSize <= 16 || (listSize-28-headerSize)%sigSize != 0 {
			return nil, fmt.Errorf("%w: signature list sizes %d/%d/%d", ErrMalformed, listSize, headerSize, sigSize)
		}
		kind := ""
		switch typ {
		case certX509:
			kind = "x509"
		case certSHA256:
			kind = "sha256"
			if sigSize != 16+sha256.Size {
				return nil, fmt.Errorf("%w: SHA-256 entries of %d bytes", ErrMalformed, sigSize)
			}
		default:
			return nil, fmt.Errorf("%w: signature type %x isn't X.509 or SHA-256", ErrMalformed, typ)
		}
		for e := off + 28 + headerSize; e < off+listSize; e += sigSize {
			var en Entry
			en.Type = kind
			copy(en.Owner[:], b[e:e+16])
			en.Data = append([]byte(nil), b[e+16:e+sigSize]...)
			out = append(out, en)
		}
		off += listSize
	}
	return out, nil
}

// X509List builds one EFI_SIGNATURE_LIST holding certDER, owned by owner.
func X509List(owner [16]byte, certDER []byte) []byte {
	var b bytes.Buffer
	b.Write(certX509[:])
	_ = binary.Write(&b, binary.LittleEndian, uint32(28+16+len(certDER))) // #nosec G115 -- a certificate is far below 4 GiB
	_ = binary.Write(&b, binary.LittleEndian, uint32(0))
	_ = binary.Write(&b, binary.LittleEndian, uint32(16+len(certDER))) // #nosec G115 -- as above
	b.Write(owner[:])
	b.Write(certDER)
	return b.Bytes()
}

// ParseGUID turns the text form of a GUID into its on-disk bytes.
func ParseGUID(s string) ([16]byte, error) {
	var g [16]byte
	var p [5]uint64
	if n, err := fmt.Sscanf(s, "%08x-%04x-%04x-%04x-%012x", &p[0], &p[1], &p[2], &p[3], &p[4]); err != nil || n != 5 || len(s) != 36 {
		return g, fmt.Errorf("efiauth: %q isn't a GUID", s)
	}
	binary.LittleEndian.PutUint32(g[0:], uint32(p[0])) // #nosec G115 -- scanned as 8 hex digits
	binary.LittleEndian.PutUint16(g[4:], uint16(p[1])) // #nosec G115 -- 4 hex digits
	binary.LittleEndian.PutUint16(g[6:], uint16(p[2])) // #nosec G115 -- 4 hex digits
	binary.BigEndian.PutUint16(g[8:], uint16(p[3]))    // #nosec G115 -- 4 hex digits
	var node [8]byte
	binary.BigEndian.PutUint64(node[:], p[4])
	copy(g[10:], node[2:])
	return g, nil
}

func mustGUID(s string) [16]byte {
	g, err := ParseGUID(s)
	if err != nil {
		panic(err)
	}
	return g
}
