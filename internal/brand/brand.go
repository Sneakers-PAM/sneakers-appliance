// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package brand reads a product bundle's brand (docs/artifact.md, the
// product bundle's brand folder): the logo and colours the box-state pages
// show while the product is away. The bundle build and the box's install
// refuse a malformed brand; edgefall reads the installed one with the same
// checks and keeps its base look when it doesn't pass.
package brand

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"image/png"
	"io"
	"io/fs"
	"math"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// The brand folder in a product bundle, and its manifest.
const (
	Dir  = "brand"
	File = "brand.yaml"
)

// Limits.
const (
	MaxManifest = 4 << 10
	MaxLogo     = 64 << 10
	// MaxSide bounds a PNG logo's width and height, in pixels.
	MaxSide = 2048
	// maxDepth and maxElements bound an SVG logo's tree.
	maxDepth    = 32
	maxElements = 4096
)

// WCAG AA: body text on the background, and the accent (the spinner and
// the Reload button) on the background as a non-text element.
const (
	MinTextContrast   = 4.5
	MinAccentContrast = 3.0
)

// The logo's file names, and the type each is served as.
var logoTypes = map[string]string{"logo.svg": "image/svg+xml", "logo.png": "image/png"}

// Colours are the page's colours, as lower-case #rrggbb.
type Colours struct {
	Background, Text, Accent string
}

// Brand is a checked brand. Logo is nil without one; Colours is nil
// without them, or when they fail the contrast check.
type Brand struct {
	Logo     []byte
	LogoType string
	Colours  *Colours
}

type manifest struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Logo       string `yaml:"logo"`
	Colours    *struct {
		Background string `yaml:"background"`
		Text       string `yaml:"text"`
		Accent     string `yaml:"accent"`
	} `yaml:"colours"`
}

var hexRE = regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`)

func refuse(format string, a ...any) error {
	return codes.New(codes.KitBundleMismatch, "the brand "+format, a...)
}

// Load reads and checks the brand folder fsys. A malformed brand is an
// error; colours that fail the contrast check are dropped with a warning,
// so the base colours stay and the logo still shows.
func Load(fsys fs.FS) (*Brand, []string, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, nil, refuse("folder can't be read: %v", err)
	}
	raw, err := readCapped(fsys, File, MaxManifest)
	if err != nil {
		return nil, nil, err
	}
	var m manifest
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, nil, refuse("%s doesn't parse: %v", File, err)
	}
	if m.APIVersion != "sneakers-pam/v1alpha1" || m.Kind != "Brand" {
		return nil, nil, refuse("%s is %s %s, not a sneakers-pam/v1alpha1 Brand", File, m.APIVersion, m.Kind)
	}
	if m.Logo == "" && m.Colours == nil {
		return nil, nil, refuse("%s names neither a logo nor colours", File)
	}
	allowed := map[string]bool{File: true}
	b := &Brand{}
	if m.Logo != "" {
		typ, ok := logoTypes[m.Logo]
		if !ok {
			return nil, nil, refuse("logo %q isn't logo.svg or logo.png", m.Logo)
		}
		allowed[m.Logo] = true
		logo, err := readCapped(fsys, m.Logo, MaxLogo)
		if err != nil {
			return nil, nil, err
		}
		if typ == "image/png" {
			err = checkPNG(logo)
		} else {
			err = checkSVG(logo)
		}
		if err != nil {
			return nil, nil, err
		}
		b.Logo, b.LogoType = logo, typ
	}
	for _, e := range entries {
		if !allowed[e.Name()] {
			return nil, nil, refuse("folder holds %s, which it never carries", e.Name())
		}
	}
	var warn []string
	if c := m.Colours; c != nil {
		for name, v := range map[string]string{"background": c.Background, "text": c.Text, "accent": c.Accent} {
			if !hexRE.MatchString(v) {
				return nil, nil, refuse("colour %s is %q, not #rrggbb", name, v)
			}
		}
		cols := Colours{Background: strings.ToLower(c.Background), Text: strings.ToLower(c.Text), Accent: strings.ToLower(c.Accent)}
		tc, ac := Contrast(cols.Text, cols.Background), Contrast(cols.Accent, cols.Background)
		switch {
		case tc < MinTextContrast:
			warn = append(warn, fmt.Sprintf("the brand's text on its background has contrast %.2f, under %.1f (WCAG AA); the base colours stay", tc, MinTextContrast))
		case ac < MinAccentContrast:
			warn = append(warn, fmt.Sprintf("the brand's accent on its background has contrast %.2f, under %.1f (WCAG AA); the base colours stay", ac, MinAccentContrast))
		default:
			b.Colours = &cols
		}
	}
	return b, warn, nil
}

func readCapped(fsys fs.FS, name string, max int64) ([]byte, error) {
	st, err := fs.Stat(fsys, name)
	if err != nil {
		return nil, refuse("has no %s", name)
	}
	if !st.Mode().IsRegular() {
		return nil, refuse("%s isn't a file", name)
	}
	f, err := fsys.Open(name)
	if err != nil {
		return nil, refuse("%s can't be opened: %v", name, err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, refuse("%s can't be read: %v", name, err)
	}
	if int64(len(b)) > max {
		return nil, refuse("%s is over %d bytes", name, max)
	}
	return b, nil
}

func checkPNG(b []byte) error {
	cfg, err := png.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		return refuse("logo.png isn't a PNG: %v", err)
	}
	if cfg.Width < 1 || cfg.Height < 1 || cfg.Width > MaxSide || cfg.Height > MaxSide {
		return refuse("logo.png is %dx%d pixels; at most %d a side", cfg.Width, cfg.Height, MaxSide)
	}
	if _, err := png.Decode(bytes.NewReader(b)); err != nil {
		return refuse("logo.png doesn't decode: %v", err)
	}
	return nil
}

const (
	svgNS   = "http://www.w3.org/2000/svg"
	xlinkNS = "http://www.w3.org/1999/xlink"
	xmlNS   = "http://www.w3.org/XML/1998/namespace"
)

// The SVG a logo may use: shapes, text, gradients, clips and masks, and
// same-file references. No script, style, animation, link, image or
// foreign content, and no event attributes: a logo that has any is
// refused, never cleaned.
var svgElements = set("svg", "g", "defs", "title", "desc", "path", "rect", "circle", "ellipse", "line", "polyline", "polygon",
	"text", "tspan", "linearGradient", "radialGradient", "stop", "clipPath", "mask", "use", "symbol")

var svgAttrs = set("id", "class", "version", "baseProfile", "viewBox", "preserveAspectRatio", "width", "height", "x", "y",
	"x1", "y1", "x2", "y2", "cx", "cy", "r", "rx", "ry", "fx", "fy", "fr", "d", "points", "pathLength", "transform",
	"fill", "fill-opacity", "fill-rule", "stroke", "stroke-width", "stroke-opacity", "stroke-linecap", "stroke-linejoin",
	"stroke-miterlimit", "stroke-dasharray", "stroke-dashoffset", "opacity", "color", "display", "visibility", "overflow",
	"offset", "stop-color", "stop-opacity", "gradientUnits", "gradientTransform", "spreadMethod",
	"clip-path", "clip-rule", "clipPathUnits", "mask", "maskUnits", "maskContentUnits",
	"font-family", "font-size", "font-weight", "font-style", "text-anchor", "dominant-baseline", "letter-spacing",
	"word-spacing", "dx", "dy", "href")

var (
	localRef = regexp.MustCompile(`^#[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)
	localURL = regexp.MustCompile(`^url\(#[A-Za-z_][A-Za-z0-9_.-]{0,63}\)$`)
)

func set(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

func checkSVG(b []byte) error {
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = true
	depth, elements, roots := 0, 0, 0
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return refuse("logo.svg isn't well-formed XML: %v", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := t.Name
			if depth == 0 {
				roots++
				if roots > 1 || n.Local != "svg" {
					return refuse("logo.svg's root isn't one svg element")
				}
			}
			depth++
			elements++
			if depth > maxDepth || elements > maxElements {
				return refuse("logo.svg is nested deeper than %d or has over %d elements", maxDepth, maxElements)
			}
			if n.Space != svgNS || !svgElements[n.Local] {
				return refuse("logo.svg has a %s element, which a logo never needs", n.Local)
			}
			if err := checkAttrs(t); err != nil {
				return err
			}
		case xml.EndElement:
			depth--
		case xml.ProcInst:
			if t.Target != "xml" {
				return refuse("logo.svg has a %s processing instruction", t.Target)
			}
		case xml.Directive:
			return refuse("logo.svg has a DOCTYPE or another directive")
		}
	}
	if roots != 1 {
		return refuse("logo.svg has no svg element")
	}
	return nil
}

func checkAttrs(t xml.StartElement) error {
	e := t.Name
	for _, a := range t.Attr {
		q := a.Name
		name, v := q.Local, strings.TrimSpace(a.Value)
		switch {
		case q.Space == "xmlns" || (q.Space == "" && name == "xmlns"):
			if v != svgNS && v != xlinkNS {
				return refuse("logo.svg declares the namespace %q", v)
			}
			continue
		case q.Space == xmlNS && name == "space":
			continue
		case q.Space == xlinkNS && name == "href", q.Space == "" && name == "href":
			if !localRef.MatchString(v) {
				return refuse("logo.svg's %s refers outside the file", e.Local)
			}
			continue
		case q.Space != "" || !svgAttrs[name]:
			return refuse("logo.svg's %s has a %s attribute, which a logo never needs", e.Local, name)
		}
		if strings.Contains(strings.ToLower(v), "url(") && !localURL.MatchString(v) {
			return refuse("logo.svg's %s refers outside the file", e.Local)
		}
	}
	return nil
}

// Contrast is the WCAG contrast ratio of two #rrggbb colours.
func Contrast(a, b string) float64 {
	la, lb := luminance(a), luminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

func luminance(hex string) float64 {
	ch := func(i int) float64 {
		v, _ := strconv.ParseUint(hex[i:i+2], 16, 8)
		c := float64(v) / 255
		if c <= 0.04045 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	return 0.2126*ch(1) + 0.7152*ch(3) + 0.0722*ch(5)
}
