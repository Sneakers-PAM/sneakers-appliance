// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package brand_test

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/brand"
)

const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 120 40" width="120" height="40">
  <title>Example</title>
  <defs><linearGradient id="g"><stop offset="0" stop-color="#ffb000"/><stop offset="1" stop-color="#ff6a00"/></linearGradient></defs>
  <rect x="0" y="0" width="40" height="40" rx="6" fill="url(#g)"/>
  <use xlink:href="#g"/>
  <text x="48" y="28" font-family="sans-serif" font-size="20" fill="#ffffff">Example</text>
</svg>
`

const manifest = `apiVersion: sneakers-pam/v1alpha1
kind: Brand
logo: logo.svg
colours:
  background: "#0b1f33"
  text: "#ffffff"
  accent: "#ffb000"
`

func tree(files map[string]string) fstest.MapFS {
	m := fstest.MapFS{}
	for k, v := range files {
		m[k] = &fstest.MapFile{Data: []byte(v), Mode: 0o644}
	}
	return m
}

func pngOf(t *testing.T, w, h int) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	img.Set(0, 0, color.RGBA{255, 0, 0, 255})
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestABrandWithASVGLogoAndColoursLoads(t *testing.T) {
	b, warn, err := brand.Load(tree(map[string]string{"brand.yaml": manifest, "logo.svg": svg}))
	if err != nil || len(warn) > 0 {
		t.Fatalf("%v %v", err, warn)
	}
	if b.LogoType != "image/svg+xml" || string(b.Logo) != svg {
		t.Fatalf("logo %q", b.LogoType)
	}
	if b.Colours == nil || *b.Colours != (brand.Colours{Background: "#0b1f33", Text: "#ffffff", Accent: "#ffb000"}) {
		t.Fatalf("colours %+v", b.Colours)
	}
}

func TestAPNGLogoAloneLoads(t *testing.T) {
	m := "apiVersion: sneakers-pam/v1alpha1\nkind: Brand\nlogo: logo.png\n"
	b, _, err := brand.Load(tree(map[string]string{"brand.yaml": m, "logo.png": pngOf(t, 64, 32)}))
	if err != nil || b.LogoType != "image/png" || b.Colours != nil {
		t.Fatalf("%+v %v", b, err)
	}
}

func TestColoursAloneLoad(t *testing.T) {
	m := "apiVersion: sneakers-pam/v1alpha1\nkind: Brand\ncolours: {background: \"#FFFFFF\", text: \"#111111\", accent: \"#0050A0\"}\n"
	b, _, err := brand.Load(tree(map[string]string{"brand.yaml": m}))
	if err != nil || b.Logo != nil || b.Colours == nil || b.Colours.Background != "#ffffff" {
		t.Fatalf("%+v %v", b, err)
	}
}

// A pair that fails WCAG AA isn't refused: the base colours stay, with a
// warning, and the logo still shows.
func TestPoorContrastFallsBackToTheBaseColoursWithAWarning(t *testing.T) {
	for name, cols := range map[string]string{
		"text":   `{background: "#777777", text: "#888888", accent: "#ffffff"}`,
		"accent": `{background: "#000000", text: "#ffffff", accent: "#202020"}`,
	} {
		m := "apiVersion: sneakers-pam/v1alpha1\nkind: Brand\nlogo: logo.svg\ncolours: " + cols + "\n"
		b, warn, err := brand.Load(tree(map[string]string{"brand.yaml": m, "logo.svg": svg}))
		if err != nil || b.Colours != nil || b.Logo == nil || len(warn) != 1 || !strings.Contains(warn[0], "contrast") {
			t.Fatalf("%s: %+v %v %v", name, b, warn, err)
		}
	}
}

func TestAMalformedBrandIsRefused(t *testing.T) {
	big := "<svg xmlns=\"http://www.w3.org/2000/svg\">" + strings.Repeat("<g/>", 20000) + "</svg>"
	for name, files := range map[string]map[string]string{
		"no manifest":       {"logo.svg": svg},
		"wrong kind":        {"brand.yaml": strings.Replace(manifest, "kind: Brand", "kind: Release", 1), "logo.svg": svg},
		"unknown field":     {"brand.yaml": manifest + "script: x\n", "logo.svg": svg},
		"empty":             {"brand.yaml": "apiVersion: sneakers-pam/v1alpha1\nkind: Brand\n"},
		"bad hex":           {"brand.yaml": strings.Replace(manifest, "#0b1f33", "red", 1), "logo.svg": svg},
		"short hex":         {"brand.yaml": strings.Replace(manifest, "#0b1f33", "#000", 1), "logo.svg": svg},
		"css injection":     {"brand.yaml": strings.Replace(manifest, `"#0b1f33"`, `"#000000;background:url(x)"`, 1), "logo.svg": svg},
		"missing colour":    {"brand.yaml": strings.Replace(manifest, "  accent: \"#ffb000\"\n", "", 1), "logo.svg": svg},
		"logo missing":      {"brand.yaml": manifest},
		"logo other name":   {"brand.yaml": strings.Replace(manifest, "logo.svg", "../logo.svg", 1), "logo.svg": svg},
		"logo gif":          {"brand.yaml": strings.Replace(manifest, "logo.svg", "logo.gif", 1), "logo.gif": "GIF89a"},
		"extra file":        {"brand.yaml": manifest, "logo.svg": svg, "font.woff": "x"},
		"too big":           {"brand.yaml": manifest, "logo.svg": big},
		"png not png":       {"brand.yaml": strings.Replace(manifest, "logo.svg", "logo.png", 1), "logo.png": svg},
		"svg not svg":       {"brand.yaml": manifest, "logo.svg": "<html><script>alert(1)</script></html>"},
		"svg not xml":       {"brand.yaml": manifest, "logo.svg": "<svg xmlns=\"http://www.w3.org/2000/svg\"><g></svg>"},
		"manifest too big":  {"brand.yaml": manifest + "#" + strings.Repeat("x", 8<<10) + "\n", "logo.svg": svg},
		"manifest not yaml": {"brand.yaml": "{", "logo.svg": svg},
	} {
		if _, _, err := brand.Load(tree(files)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAHugePNGIsRefused(t *testing.T) {
	m := "apiVersion: sneakers-pam/v1alpha1\nkind: Brand\nlogo: logo.png\n"
	if _, _, err := brand.Load(tree(map[string]string{"brand.yaml": m, "logo.png": pngOf(t, 4096, 1)})); err == nil {
		t.Fatal("a 4096-pixel-wide PNG was accepted")
	}
}

// No script and nothing that reaches outside the file: an SVG with any of
// these is refused, never cleaned.
func TestAnSVGThatCouldRunOrFetchIsRefused(t *testing.T) {
	open := `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 10 10">`
	for name, body := range map[string]string{
		"script":          `<script>alert(1)</script>`,
		"script ns":       `<svg:script xmlns:svg="http://www.w3.org/2000/svg">alert(1)</svg:script>`,
		"onload":          `<rect width="1" height="1" onload="alert(1)"/>`,
		"ONCLICK":         `<rect width="1" height="1" ONCLICK="alert(1)"/>`,
		"foreignObject":   `<foreignObject><div xmlns="http://www.w3.org/1999/xhtml">x</div></foreignObject>`,
		"image":           `<image href="https://example.org/x.png"/>`,
		"external use":    `<use href="https://example.org/x.svg#a"/>`,
		"xlink js":        `<use xlink:href="javascript:alert(1)"/>`,
		"anchor":          `<a href="javascript:alert(1)"><rect width="1" height="1"/></a>`,
		"style element":   `<style>rect{fill:url(https://example.org/x)}</style>`,
		"style attribute": `<rect width="1" height="1" style="fill:red"/>`,
		"external fill":   `<rect width="1" height="1" fill="url(https://example.org/x#a)"/>`,
		"animate":         `<animate attributeName="href" to="javascript:alert(1)"/>`,
		"set":             `<set attributeName="onmouseover" to="alert(1)"/>`,
		"other ns attr":   `<rect width="1" height="1" xmlns:ev="http://www.w3.org/2001/xml-events" ev:event="click"/>`,
		"proc inst":       `<?xml-stylesheet href="https://example.org/x.css"?>`,
	} {
		m := tree(map[string]string{"brand.yaml": manifest, "logo.svg": open + body + `</svg>`})
		if _, _, err := brand.Load(m); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	doctype := `<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]>` + open + `<text>&x;</text></svg>`
	if _, _, err := brand.Load(tree(map[string]string{"brand.yaml": manifest, "logo.svg": doctype})); err == nil {
		t.Error("doctype: accepted")
	}
	html := `<html xmlns="http://www.w3.org/1999/xhtml"><body/></html>`
	if _, _, err := brand.Load(tree(map[string]string{"brand.yaml": manifest, "logo.svg": html})); err == nil {
		t.Error("an html root: accepted")
	}
}

func TestContrastIsWCAGRelativeLuminance(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want float64
	}{{"#000000", "#ffffff", 21}, {"#ffffff", "#ffffff", 1}, {"#767676", "#ffffff", 4.54}} {
		if got := brand.Contrast(c.a, c.b); got < c.want-0.01 || got > c.want+0.01 {
			t.Errorf("%s on %s: %.3f, want %.2f", c.a, c.b, got, c.want)
		}
	}
}
