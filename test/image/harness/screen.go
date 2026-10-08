// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// Kernel is the bzImage the disk under test boots; the screen is read with
// the font compiled into it.
var Kernel = envOr("SNEAKERS_KERNEL", "")

// glyphs is one of fbcon's built-in fonts: its cell, and each printable
// character's bitmap (a row a byte, or two for a 16-wide cell).
type glyphs struct {
	w, h int
	char map[string]byte
}

// The built-in fonts the screen may be drawn in: the large Terminus the
// UKI selects, and the 8x16 the console falls back to on a small screen.
var builtIn = []struct {
	name string
	w, h int
}{{"TER16x32", 16, 32}, {"VGA8x16", 8, 16}}

var (
	fontMu    sync.Mutex
	fontCache = map[string][]glyphs{}
)

// fonts reads fbcon's built-in fonts out of the kernel the image boots:
// the payload is xz (with the x86 filter, so the xz tool unpacks it), and
// each font is the table that follows its header {0, 0, size, 0}. Reading
// them from the kernel keeps the test on the exact glyphs the screen is
// drawn with, without a copy of a font in this repo.
func fonts(t testing.TB) []glyphs {
	t.Helper()
	Need(t, []string{"xz"}, Kernel)
	fontMu.Lock()
	defer fontMu.Unlock()
	if g, ok := fontCache[Kernel]; ok {
		return g
	}
	img, err := os.ReadFile(Kernel) // #nosec G304 -- the kernel under test
	if err != nil {
		t.Fatal(err)
	}
	at := bytes.Index(img, []byte("\xfd7zXZ\x00"))
	if at < 0 {
		t.Fatalf("%s: no xz payload", Kernel)
	}
	cmd := exec.Command("xz", "-dc", "--single-stream") // #nosec G204 -- test-only, fixed tool
	cmd.Stdin = bytes.NewReader(img[at:])
	vmlinux, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s: unpack the payload: %v", Kernel, err)
	}
	var out []glyphs
	for _, f := range builtIn {
		g, err := findFont(vmlinux, f.w, f.h)
		if err != nil {
			t.Logf("%s: %s: %v", Kernel, f.name, err)
			continue
		}
		out = append(out, g)
	}
	if len(out) == 0 {
		t.Fatalf("%s: no built-in font (CONFIG_FONT_TER16x32, CONFIG_FONT_8x16)", Kernel)
	}
	fontCache[Kernel] = out
	return out
}

func findFont(vmlinux []byte, w, h int) (glyphs, error) {
	bpr := (w + 7) / 8
	cell := bpr * h
	size := 256 * cell
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[8:], uint32(size)) // #nosec G115 -- a small font size
	for off := 0; ; {
		i := bytes.Index(vmlinux[off:], hdr)
		if i < 0 {
			return glyphs{}, fmt.Errorf("no %dx%d font in the kernel", w, h)
		}
		off += i + len(hdr)
		if off+size > len(vmlinux) {
			continue
		}
		data := vmlinux[off : off+size]
		glyph := func(c int) []byte { return data[c*cell : (c+1)*cell] }
		// A CP437 font's shape: space is blank, 0xDB is a full block, and
		// every letter has ink. (Terminus draws a glyph at NUL.)
		blank := make([]byte, cell)
		if !bytes.Equal(glyph(' '), blank) ||
			!bytes.Equal(glyph(0xdb), bytes.Repeat([]byte{0xff}, cell)) || bytes.Equal(glyph('A'), blank) {
			continue
		}
		g := glyphs{w: w, h: h, char: map[string]byte{}}
		for c := 0x7e; c >= 0x20; c-- {
			g.char[string(glyph(c))] = byte(c)
		}
		return g, nil
	}
}

// screenText decodes a P6 screendump into its text rows in font g: each
// cell is matched, as lit and unlit pixels, against the font. A cell that
// isn't a printable character (the cursor, a logo) reads as '?'.
func screenText(ppm []byte, g glyphs) ([]string, error) {
	r := bufio.NewReader(bytes.NewReader(ppm))
	var magic string
	var w, h, maxv int
	if _, err := fmt.Fscan(r, &magic, &w, &h, &maxv); err != nil || magic != "P6" || maxv != 255 {
		return nil, fmt.Errorf("not a P6 screendump: %v", err)
	}
	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}
	px := make([]byte, w*h*3)
	if _, err := io.ReadFull(r, px); err != nil {
		return nil, err
	}
	lit := func(x, y int) bool {
		p := px[(y*w+x)*3:]
		return p[0]|p[1]|p[2] != 0
	}
	bpr := (g.w + 7) / 8
	rows := make([]string, 0, h/g.h)
	for cy := 0; cy+g.h <= h; cy += g.h {
		var line []byte
		for cx := 0; cx+g.w <= w; cx += g.w {
			k := make([]byte, bpr*g.h)
			for y := 0; y < g.h; y++ {
				for x := 0; x < g.w; x++ {
					if lit(cx+x, cy+y) {
						k[y*bpr+x/8] |= 0x80 >> (x % 8)
					}
				}
			}
			c, ok := g.char[string(k)]
			if !ok {
				c = '?'
			}
			line = append(line, c)
		}
		rows = append(rows, string(line))
	}
	return rows, nil
}

// legible counts the cells read as text other than blanks.
func legible(rows []string) int {
	n := 0
	for _, r := range rows {
		for _, c := range r {
			if c != ' ' && c != '?' {
				n++
			}
		}
	}
	return n
}

// qmp sends one QMP command to the VM and returns its reply.
func (vm *VM) qmp(cmd string, args any) error {
	conn, err := net.DialTimeout("unix", vm.qmpSock, 5*time.Second)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	rd := bufio.NewReader(conn)
	enc := json.NewEncoder(conn)
	reply := func() error {
		for {
			line, err := rd.ReadBytes('\n')
			if err != nil {
				return err
			}
			var m map[string]json.RawMessage
			if err := json.Unmarshal(line, &m); err != nil {
				return err
			}
			if e, ok := m["error"]; ok {
				return fmt.Errorf("qmp %s: %s", cmd, e)
			}
			if _, ok := m["return"]; ok {
				return nil
			}
		}
	}
	if _, err := rd.ReadBytes('\n'); err != nil { // the greeting
		return err
	}
	if err := enc.Encode(map[string]any{"execute": "qmp_capabilities"}); err != nil {
		return err
	}
	if err := reply(); err != nil {
		return err
	}
	msg := map[string]any{"execute": cmd}
	if args != nil {
		msg["arguments"] = args
	}
	if err := enc.Encode(msg); err != nil {
		return err
	}
	return reply()
}

// Screen is the text on the VM's display now, one string per row.
func (vm *VM) Screen() []string {
	vm.t.Helper()
	rows, err := vm.screen()
	if err != nil {
		vm.t.Fatal(err)
	}
	return rows
}

func (vm *VM) screen() ([]string, error) {
	fs := fonts(vm.t)
	shot := filepath.Join(vm.dir, "screen.ppm")
	if err := vm.qmp("screendump", map[string]string{"filename": shot}); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(shot) // #nosec G304 -- the VM's own screendump
	if err != nil {
		return nil, err
	}
	// The screen is in whichever font reads it best: the large one, or
	// the small one before fbcon switches (the firmware's, the boot) and
	// on a small screen.
	var best []string
	for _, g := range fs {
		rows, err := screenText(b, g)
		if err != nil {
			return nil, err
		}
		if best == nil || legible(rows) > legible(best) {
			best = rows
		}
	}
	return best, nil
}

var spaces = regexp.MustCompile(`\s+`)

// flat joins the rows, which wrap at the screen's edge, and squeezes runs
// of blanks to one space, so a long line matches as one.
func flat(rows []string) string { return spaces.ReplaceAllString(strings.Join(rows, ""), " ") }

// ExpectScreen waits until the display shows re, or fails the test. Rows
// are joined as wrapped and blanks squeezed to single spaces.
func (vm *VM) ExpectScreen(re string, timeout time.Duration) string {
	vm.t.Helper()
	rx := regexp.MustCompile(re)
	deadline := time.Now().Add(timeout)
	for {
		rows, err := vm.screen()
		if err == nil {
			if m := rx.FindString(flat(rows)); m != "" {
				return m
			}
		}
		if time.Now().After(deadline) || vm.exited() {
			vm.t.Fatalf("the display never showed %q in %s; it shows:\n%s", re, timeout, strings.Join(trimRows(rows), "\n"))
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func trimRows(rows []string) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, strings.TrimRight(r, " "))
	}
	return out
}

// qcodes are QEMU's key names for the characters Press types.
var qcodes = map[rune]string{' ': "spc", '\r': "ret", '\n': "ret", '=': "equal", '-': "minus", '.': "dot", '/': "slash", ',': "comma"}

// Press types s on the VM's keyboard (lower-case letters, digits, space,
// Enter and a little punctuation).
func (vm *VM) Press(s string) {
	vm.t.Helper()
	for _, c := range s {
		k, ok := qcodes[c]
		switch {
		case ok:
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			k = string(c)
		default:
			vm.t.Fatalf("Press: no key for %q", c)
		}
		if err := vm.qmp("send-key", map[string]any{"keys": []map[string]string{{"type": "qcode", "data": k}}}); err != nil {
			vm.t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
