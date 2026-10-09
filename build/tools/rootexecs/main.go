// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command rootexecs checks a staged root tree holds every program the
// box's code and service tables run: each absolute /bin, /sbin, /usr/bin,
// /usr/sbin or /usr/libexec path in cmd/ and internal/ (tests left out),
// and every exec, pre-start and leading args path in the service tables,
// must be an executable file in the tree, following links. A link into
// /var is the running box's (the installed product's kubectl) and isn't
// checked. The root build runs it before it packs the image, so a root
// without cryptsetup, mkfs.ext4 or sgdisk never ships.
//
// Usage: rootexecs --src <repository> --tree <staged root> --services <dir>...
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

var (
	codePath = regexp.MustCompile(`"(/(?:usr/)?s?bin/[A-Za-z0-9._+-]+|/usr/libexec/[A-Za-z0-9._/+-]+)"`)
	svcExec  = regexp.MustCompile(`(?m)^exec:\s*(/[^\s#]+)`)
	svcList  = regexp.MustCompile(`(?m)^(?:pre-start|args):\s*\[\s*(/[^,\s\]]+)`)
)

// notRun are paths the code names that nothing executes: the service
// accounts' login shell field in /etc/passwd.
var notRun = []string{"/usr/sbin/nologin"}

func execd(src string, services []string) ([]string, error) {
	var out []string
	add := func(p string) {
		if !strings.HasPrefix(p, "/var/") && !slices.Contains(notRun, p) && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(src, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && d.Name() == "testutil" {
				return filepath.SkipDir
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(p) // #nosec G304 G122 -- the repository's own source, read by a build tool
			if err != nil {
				return err
			}
			for _, m := range codePath.FindAllStringSubmatch(string(b), -1) {
				add(m[1])
			}
			return nil
		})
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	for _, dir := range services {
		files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			b, err := os.ReadFile(f) // #nosec G304 -- a service table in the repository
			if err != nil {
				return nil, err
			}
			for _, re := range []*regexp.Regexp{svcExec, svcList} {
				for _, m := range re.FindAllStringSubmatch(string(b), -1) {
					add(m[1])
				}
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

// check returns the paths that aren't an executable file in tree, each
// with what it resolved to.
func check(tree string, paths []string) []string {
	var missing []string
	for _, p := range paths {
		if r, ok := resolve(tree, p); !ok {
			missing = append(missing, p+" (-> "+r+")")
		}
	}
	return missing
}

func resolve(tree, p string) (string, bool) {
	for range 40 {
		if strings.HasPrefix(p, "/var/") {
			return p, true
		}
		full := filepath.Join(tree, p)
		fi, err := os.Lstat(full)
		if err != nil {
			return p, false
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			return p, fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
		}
		t, err := os.Readlink(full)
		if err != nil {
			return p, false
		}
		if !path.IsAbs(t) {
			t = path.Join(path.Dir(p), t)
		}
		p = t
	}
	return p, false
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	var src, tree string
	var services multi
	flag.StringVar(&src, "src", ".", "the repository")
	flag.StringVar(&tree, "tree", "", "the staged root tree")
	flag.Var(&services, "services", "a service table directory (repeatable)")
	flag.Parse()
	if tree == "" {
		fmt.Fprintln(os.Stderr, "usage: rootexecs --src <repository> --tree <staged root> --services <dir>...")
		os.Exit(2)
	}
	paths, err := execd(src, services)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rootexecs:", err)
		os.Exit(1)
	}
	missing := check(tree, paths)
	for _, m := range missing {
		fmt.Fprintln(os.Stderr, "rootexecs: missing or not executable in the root:", m)
	}
	if len(missing) > 0 {
		os.Exit(1)
	}
	fmt.Printf("rootexecs: all %d programs the code and the service tables run are in the root\n", len(paths))
}
