// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package rootshell is the wire between a closed shell and accessd's
// root-shell socket (/run/sneakers/rootshell.sock). The closed shell sends
// one JSON line, the handshake with its ticket and terminal size, then
// frames: data typed at the terminal, or a new terminal size. accessd
// sends back the root shell's output as plain bytes.
package rootshell

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxHandshake bounds the handshake line.
const MaxHandshake = 4096

// The frame types.
const (
	frameData   byte = 0
	frameResize byte = 1
)

// Handshake opens the root shell.
type Handshake struct {
	Ticket string `json:"ticket"`
	Term   string `json:"term,omitempty"`
	Rows   uint16 `json:"rows,omitempty"`
	Cols   uint16 `json:"cols,omitempty"`
}

// WriteHandshake sends h as one line.
func WriteHandshake(w io.Writer, h Handshake) error {
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// ReadHandshake reads the handshake line and returns the reader positioned
// after it.
func ReadHandshake(r io.Reader) (Handshake, io.Reader, error) {
	br := bufio.NewReaderSize(r, MaxHandshake)
	line, err := br.ReadSlice('\n')
	if err != nil {
		return Handshake{}, br, fmt.Errorf("rootshell: the handshake: %w", err)
	}
	var h Handshake
	if err := json.Unmarshal(line, &h); err != nil {
		return Handshake{}, br, fmt.Errorf("rootshell: the handshake doesn't parse: %w", err)
	}
	if h.Ticket == "" {
		return Handshake{}, br, errors.New("rootshell: the handshake has no ticket")
	}
	return h, br, nil
}

// WriteData sends typed bytes, in frames of at most 64 KiB.
func WriteData(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n := min(len(p), 0xffff)
		hdr := []byte{frameData, 0, 0}
		binary.BigEndian.PutUint16(hdr[1:], uint16(n)) // #nosec G115 -- at most 0xffff
		if _, err := w.Write(append(hdr, p[:n]...)); err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

// WriteResize sends a new terminal size.
func WriteResize(w io.Writer, rows, cols uint16) error {
	b := []byte{frameResize, 0, 4, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(b[3:], rows)
	binary.BigEndian.PutUint16(b[5:], cols)
	_, err := w.Write(b)
	return err
}

type reader struct {
	r        io.Reader
	onResize func(rows, cols uint16)
	left     int
}

// NewReader returns the data in r's frames; each size frame goes to
// onResize.
func NewReader(r io.Reader, onResize func(rows, cols uint16)) io.Reader {
	return &reader{r: r, onResize: onResize}
}

func (f *reader) Read(p []byte) (int, error) {
	for f.left == 0 {
		var hdr [3]byte
		if _, err := io.ReadFull(f.r, hdr[:]); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return 0, io.EOF
			}
			return 0, err
		}
		n := int(binary.BigEndian.Uint16(hdr[1:]))
		switch hdr[0] {
		case frameData:
			f.left = n
		case frameResize:
			if n != 4 {
				return 0, errors.New("rootshell: a size frame isn't 4 bytes")
			}
			var sz [4]byte
			if _, err := io.ReadFull(f.r, sz[:]); err != nil {
				return 0, err
			}
			if f.onResize != nil {
				f.onResize(binary.BigEndian.Uint16(sz[:2]), binary.BigEndian.Uint16(sz[2:]))
			}
		default:
			return 0, fmt.Errorf("rootshell: an unknown frame type %d", hdr[0])
		}
	}
	n, err := f.r.Read(p[:min(len(p), f.left)])
	f.left -= n
	return n, err
}
