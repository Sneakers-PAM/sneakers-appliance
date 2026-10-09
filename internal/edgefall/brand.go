// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package edgefall

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/brand"
)

// look is what the page and the state carry: the base look, or the
// installed product's brand.
type look struct {
	style, csp string
	logo       []byte
	logoType   string
	// logoURI is the logo as a data: URI: the page carries it, so it
	// shows even when 443 goes away between the page and another request.
	logoURI string
	state   *stateLook
}

// stateLook is the brand in /_box/state, for the poller's overlay.
type stateLook struct {
	Background string `json:"background,omitempty"`
	Text       string `json:"text,omitempty"`
	Accent     string `json:"accent,omitempty"`
	Logo       string `json:"logo,omitempty"`
}

// logoStyle sizes the logo where the mark was.
const logoStyle = ".logo{display:block;max-width:12rem;max-height:4rem;margin:0 auto 1.5rem}"

// newLook builds the look for b; nil is the base look. The colours are
// #rrggbb values brand.Load checked, so they go into the stylesheet as
// they are, and the CSP pins the result by its hash.
func newLook(b *brand.Brand) *look {
	style := pageStyle
	var sl *stateLook
	if b != nil {
		sl = &stateLook{}
		if c := b.Colours; c != nil {
			style += fmt.Sprintf("body{background:%s;color:%s}p{color:%s}.mark{color:%s}.spin{border-color:%s;border-top-color:%s}",
				c.Background, c.Text, c.Text, c.Accent, mix(c.Accent, c.Background, 0.3), c.Accent)
			sl.Background, sl.Text, sl.Accent = c.Background, c.Text, c.Accent
		}
		if b.Logo != nil {
			style += logoStyle
			sl.Logo = LogoPath
		}
	}
	lk := &look{style: style, csp: pageCSP(style), state: sl}
	if b != nil && b.Logo != nil {
		lk.logo, lk.logoType = b.Logo, b.LogoType
		lk.logoURI = "data:" + b.LogoType + ";base64," + base64.StdEncoding.EncodeToString(b.Logo)
	}
	return lk
}

// mix is a weighted mix of two #rrggbb colours, w of a.
func mix(a, b string, w float64) string {
	out := "#"
	for i := 1; i < 7; i += 2 {
		x, _ := strconv.ParseUint(a[i:i+2], 16, 8)
		y, _ := strconv.ParseUint(b[i:i+2], 16, 8)
		out += fmt.Sprintf("%02x", int(float64(x)*w+float64(y)*(1-w)+0.5))
	}
	return out
}

// LoadBrand reads the installed product's brand from dir (the current
// slot's brand/, which only root writes) when it changed since the last
// load: the slot current names, or the files in it. With no brand the
// base look stays; with a malformed one the base look stays and the error
// says why. changed reports whether it read the brand again; warnings are
// brand.Load's (colours dropped for contrast).
func (s *Server) LoadBrand(dir string) (changed bool, warnings []string, err error) {
	key := brandKey(dir)
	if key == s.key {
		return false, nil, nil
	}
	s.key = key
	real, rerr := filepath.EvalSymlinks(dir)
	if rerr != nil {
		s.look.Store(newLook(nil))
		if errors.Is(rerr, fs.ErrNotExist) {
			return true, nil, nil
		}
		return true, nil, rerr
	}
	b, warn, err := brand.Load(os.DirFS(real))
	if err != nil {
		s.look.Store(newLook(nil))
		return true, nil, err
	}
	s.look.Store(newLook(b))
	return true, warn, nil
}

// brandKey names what LoadBrand would read: the resolved folder and its
// files' sizes and times. A slot is filled before current names it, so a
// change shows as a new path or new files.
func brandKey(dir string) string {
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "none"
	}
	var k strings.Builder
	k.WriteString(real)
	entries, err := os.ReadDir(real)
	if err != nil {
		return "unreadable " + real
	}
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			continue
		}
		fmt.Fprintf(&k, "|%s %d %d", e.Name(), fi.Size(), fi.ModTime().UnixNano())
	}
	return k.String()
}
