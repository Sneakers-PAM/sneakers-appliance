// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
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

// The kernel console's cell: fbcon's built-in 8x16 font.
const (
	cellW = 8
	cellH = 16
)

// glyphs maps each printable character's bitmap to the character.
type glyphs map[[cellH]byte]byte

var (
	fontMu    sync.Mutex
	fontCache = map[string]glyphs{}
)

// font reads fbcon's 8x16 font out of the kernel the image boots: the
// payload is xz (with the x86 filter, so the xz tool unpacks it), and the
// font is the 4096-byte table that follows its header {0, 0, 4096, 0}.
// Reading it from the kernel keeps the test on the exact glyphs the screen
// is drawn with, without a copy of the font in this repo.
func font(t testing.TB) glyphs {
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
	g, err := findFont(vmlinux)
	if err != nil {
		t.Fatalf("%s: %v", Kernel, err)
	}
	fontCache[Kernel] = g
	return g
}

func findFont(vmlinux []byte) (glyphs, error) {
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[8:], 256*cellH)
	for off := 0; ; {
		i := bytes.Index(vmlinux[off:], hdr)
		if i < 0 {
			return nil, errors.New("fbcon's 8x16 font isn't in the kernel (CONFIG_FONT_8x16)")
		}
		off += i + len(hdr)
		if off+256*cellH > len(vmlinux) {
			continue
		}
		data := vmlinux[off : off+256*cellH]
		glyph := func(c int) []byte { return data[c*cellH : (c+1)*cellH] }
		// The VGA font's shape: NUL and space are blank, 0xDB is a full
		// block, and every letter has ink.
		if !bytes.Equal(glyph(0), make([]byte, cellH)) || !bytes.Equal(glyph(' '), make([]byte, cellH)) ||
			!bytes.Equal(glyph(0xdb), bytes.Repeat([]byte{0xff}, cellH)) || bytes.Equal(glyph('A'), make([]byte, cellH)) {
			continue
		}
		g := glyphs{}
		for c := 0x7e; c >= 0x20; c-- {
			var k [cellH]byte
			copy(k[:], glyph(c))
			g[k] = byte(c)
		}
		return g, nil
	}
}

// screenText decodes a P6 screendump into its text rows: each 8x16 cell
// is matched, as lit and unlit pixels, against the font. A cell that isn't
// a printable character (the cursor, a logo) reads as '?'.
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
	rows := make([]string, 0, h/cellH)
	for cy := 0; cy+cellH <= h; cy += cellH {
		var line []byte
		for cx := 0; cx+cellW <= w; cx += cellW {
			var k [cellH]byte
			for y := 0; y < cellH; y++ {
				for x := 0; x < cellW; x++ {
					if lit(cx+x, cy+y) {
						k[y] |= 0x80 >> x
					}
				}
			}
			c, ok := g[k]
			if !ok {
				c = '?'
			}
			line = append(line, c)
		}
		rows = append(rows, string(line))
	}
	return rows, nil
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
	g := font(vm.t)
	shot := filepath.Join(vm.dir, "screen.ppm")
	if err := vm.qmp("screendump", map[string]string{"filename": shot}); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(shot) // #nosec G304 -- the VM's own screendump
	if err != nil {
		return nil, err
	}
	return screenText(b, g)
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
