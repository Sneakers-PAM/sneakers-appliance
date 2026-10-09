// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package productinfo says which product is installed, from the public
// header in the current product slot. It uses the standard library only,
// so the closed shell can name the product's command group without
// linking the bundle code. The base appliance's menus are generic; an
// installed product adds its own section under the name read here.
package productinfo

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Dir is the product slots' directory on the box.
const Dir = "/var/lib/sneakers/product"

// BundleFile is the verified header a slot holds once its bundle checks
// out.
const BundleFile = "bundle.json"

// current is the link to the slot the product runs from.
const current = "current"

// suffix ends every product bundle's header name: <product>-product.
const suffix = "-product"

// maxHeader bounds what Installed reads of a header.
const maxHeader = 64 * 1024

var wordRE = regexp.MustCompile(`^[a-z][a-z0-9]*$`)

// Info is the installed product; the zero Info is none.
type Info struct {
	// Name is the product's command word, such as "sneakers".
	Name string
	// Title is its name for people, such as "Sneakers".
	Title string
	// Version is the installed version.
	Version string
}

// Present reports whether a product is installed.
func (i Info) Present() bool { return i.Name != "" }

// Installed reads the header in dir's current slot. A box with no
// product, or a header that names none, gives the zero Info.
func Installed(dir string) Info {
	f, err := os.Open(filepath.Join(dir, current, BundleFile)) // #nosec G304 -- the current slot's public header
	if err != nil {
		return Info{}
	}
	defer func() { _ = f.Close() }()
	var h struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if json.NewDecoder(io.LimitReader(f, maxHeader)).Decode(&h) != nil {
		return Info{}
	}
	word, ok := strings.CutSuffix(h.Name, suffix)
	if !ok || !wordRE.MatchString(word) || h.Version == "" {
		return Info{}
	}
	return Info{Name: word, Title: strings.ToUpper(word[:1]) + word[1:], Version: h.Version}
}
