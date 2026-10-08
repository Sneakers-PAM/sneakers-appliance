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

// fakeFont is a made-up w x h font with a CP437 font's landmarks (blank
// NUL and space, a full block at 0xDB) and a distinct bitmap per
// character.
func fakeFont(w, h int) []byte {
	cell := (w + 7) / 8 * h
	data := make([]byte, 256*cell)
	for c := 1; c < 256; c++ {
		if c == ' ' {
			continue
		}
		g := data[c*cell : (c+1)*cell]
		g[2], g[5], g[9] = byte(c), byte(c>>1)|1, 0x81
		if c == 0xdb {
			copy(g, bytes.Repeat([]byte{0xff}, cell))
		}
	}
	return data
}

// render draws rows with font the way fbcon does: one w x h cell per
// character from the top left, lit pixels in colour on black.
func render(rows []string, cols int, font []byte, cw, ch int) []byte {
	bpr := (cw + 7) / 8
	w, h := cols*cw, len(rows)*ch
	px := make([]byte, w*h*3)
	for r, line := range rows {
		for c := 0; c < len(line); c++ {
			g := font[int(line[c])*bpr*ch:]
			for y := 0; y < ch; y++ {
				for x := 0; x < cw; x++ {
					if g[y*bpr+x/8]&(0x80>>(x%8)) != 0 {
						p := px[((r*ch+y)*w+c*cw+x)*3:]
						p[0], p[1], p[2] = 0xaa, 0x55, byte(r)
					}
				}
			}
		}
	}
	return append([]byte(fmt.Sprintf("P6\n%d %d\n255\n", w, h)), px...)
}

// Both built-in fonts read back: the large Terminus and the 8x16.
func TestTheScreenReadsBackAsText(t *testing.T) {
	for _, f := range builtIn {
		data := fakeFont(f.w, f.h)
		hdr := make([]byte, 16)
		binary.LittleEndian.PutUint32(hdr[8:], uint32(len(data))) // #nosec G115 -- a small font
		// A decoy header with a table that isn't the font comes first.
		vmlinux := append(append(append([]byte("kernel"), hdr...), make([]byte, 300)...), append(hdr, data...)...)
		g, err := findFont(vmlinux, f.w, f.h)
		if err != nil {
			t.Fatalf("%s: %v", f.name, err)
		}
		want := []string{"sneakers-init: phase=enrol", `type "no secure boot" and`, " press Enter"}
		rows, err := screenText(render(want, 26, data, f.w, f.h), g)
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimRight(rows[0], " ") != want[0] {
			t.Fatalf("%s: row 0 = %q", f.name, rows[0])
		}
		if got := flat(rows); !strings.Contains(got, `type "no secure boot" and press Enter`) {
			t.Fatalf("%s: the wrapped line reads %q", f.name, got)
		}
	}
}

// The screen is read in the font that reads it best.
func TestTheBestFontReadsTheScreen(t *testing.T) {
	big, small := fakeFont(16, 32), fakeFont(8, 16)
	gb := glyphs{w: 16, h: 32, char: map[string]byte{}}
	gs := glyphs{w: 8, h: 16, char: map[string]byte{}}
	for c := 0x20; c <= 0x7e; c++ {
		gb.char[string(big[c*64:(c+1)*64])] = byte(c)
		gs.char[string(small[c*16:(c+1)*16])] = byte(c)
	}
	shot := render([]string{"https://192.0.2.10:8443"}, 32, big, 16, 32)
	rb, _ := screenText(shot, gb)
	rs, _ := screenText(shot, gs)
	if legible(rb) <= legible(rs) || !strings.Contains(rb[0], "https://192.0.2.10:8443") {
		t.Fatalf("large %d %q, small %d", legible(rb), rb[0], legible(rs))
	}
}

func TestNoFontIsAnError(t *testing.T) {
	if _, err := findFont(make([]byte, 8192), 8, 16); err == nil {
		t.Fatal("found a font in an empty kernel")
	}
}
