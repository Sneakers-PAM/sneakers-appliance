// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// fakeFont is a made-up 8x16 font with the VGA font's landmarks (blank NUL
// and space, a full block at 0xDB) and a distinct bitmap per character.
func fakeFont() []byte {
	data := make([]byte, 256*cellH)
	for c := 1; c < 256; c++ {
		if c == ' ' {
			continue
		}
		g := data[c*cellH : (c+1)*cellH]
		g[2], g[5], g[9] = byte(c), byte(c>>1)|1, 0x81
		if c == 0xdb {
			copy(g, bytes.Repeat([]byte{0xff}, cellH))
		}
	}
	return data
}

// render draws rows with font the way fbcon does: one 8x16 cell per
// character from the top left, lit pixels in colour on black.
func render(rows []string, cols int, font []byte) []byte {
	w, h := cols*cellW, len(rows)*cellH
	px := make([]byte, w*h*3)
	for r, line := range rows {
		for c := 0; c < len(line); c++ {
			g := font[int(line[c])*cellH:]
			for y := 0; y < cellH; y++ {
				for x := 0; x < cellW; x++ {
					if g[y]&(0x80>>x) != 0 {
						p := px[((r*cellH+y)*w+c*cellW+x)*3:]
						p[0], p[1], p[2] = 0xaa, 0x55, byte(r)
					}
				}
			}
		}
	}
	return append([]byte(fmt.Sprintf("P6\n%d %d\n255\n", w, h)), px...)
}

func TestTheScreenReadsBackAsText(t *testing.T) {
	data := fakeFont()
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[8:], 256*cellH)
	// A decoy header with a table that isn't the font comes first.
	vmlinux := append(append(append([]byte("kernel"), hdr...), make([]byte, 300)...), append(hdr, data...)...)
	g, err := findFont(vmlinux)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"sneakers-init: phase=enrol", `type "no secure boot" and`, " press Enter"}
	rows, err := screenText(render(want, 26, data), g)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimRight(rows[0], " ") != want[0] {
		t.Fatalf("row 0 = %q", rows[0])
	}
	if got := flat(rows); !strings.Contains(got, `type "no secure boot" and press Enter`) {
		t.Fatalf("the wrapped line reads %q", got)
	}
}

func TestNoFontIsAnError(t *testing.T) {
	if _, err := findFont(make([]byte, 8192)); err == nil {
		t.Fatal("found a font in an empty kernel")
	}
}
