// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package k0s_test

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevated"
)

// The shell scripts the root ships run on the box's busybox, which answers
// an option it wasn't built with by exiting 1 ("unrecognized option"); a
// script under set -e only shows that as a failed step.

// busyboxGated lists the options of the applets busybox.config turns on that
// busybox builds only with a further option (busybox 1.38's Config.src).
// An option missing here isn't checked; add it when a script needs it.
var busyboxGated = map[string]map[string]string{
	"readlink": {"-f": "CONFIG_FEATURE_READLINK_FOLLOW"},
	"stat":     {"-c": "CONFIG_FEATURE_STAT_FORMAT", "-f": "CONFIG_FEATURE_STAT_FILESYSTEM"},
	"head":     {"-c": "CONFIG_FEATURE_FANCY_HEAD", "-q": "CONFIG_FEATURE_FANCY_HEAD", "-v": "CONFIG_FEATURE_FANCY_HEAD"},
	"tail":     {"-c": "CONFIG_FEATURE_FANCY_TAIL", "-q": "CONFIG_FEATURE_FANCY_TAIL", "-s": "CONFIG_FEATURE_FANCY_TAIL", "-v": "CONFIG_FEATURE_FANCY_TAIL"},
	"ls":       {"-L": "CONFIG_FEATURE_LS_FOLLOWLINKS", "-R": "CONFIG_FEATURE_LS_RECURSIVE", "-t": "CONFIG_FEATURE_LS_TIMESTAMPS", "-S": "CONFIG_FEATURE_LS_SORTFILES"},
	"grep":     {"-A": "CONFIG_FEATURE_GREP_CONTEXT", "-B": "CONFIG_FEATURE_GREP_CONTEXT", "-C": "CONFIG_FEATURE_GREP_CONTEXT"},
	"sort":     {"-k": "CONFIG_FEATURE_SORT_BIG", "-t": "CONFIG_FEATURE_SORT_BIG", "-g": "CONFIG_FEATURE_SORT_BIG", "-M": "CONFIG_FEATURE_SORT_BIG", "-s": "CONFIG_FEATURE_SORT_BIG"},
	"xargs":    {"-0": "CONFIG_FEATURE_XARGS_SUPPORT_ZERO_TERM", "-I": "CONFIG_FEATURE_XARGS_SUPPORT_REPL_STR", "-P": "CONFIG_FEATURE_XARGS_SUPPORT_PARALLEL", "-t": "CONFIG_FEATURE_XARGS_SUPPORT_CONFIRMATION"},
	"find": {
		"-type": "CONFIG_FEATURE_FIND_TYPE", "-mtime": "CONFIG_FEATURE_FIND_MTIME", "-exec": "CONFIG_FEATURE_FIND_EXEC",
		"-maxdepth": "CONFIG_FEATURE_FIND_MAXDEPTH", "-mindepth": "CONFIG_FEATURE_FIND_MAXDEPTH", "-path": "CONFIG_FEATURE_FIND_PATH",
		"-print0": "CONFIG_FEATURE_FIND_PRINT0", "-delete": "CONFIG_FEATURE_FIND_DELETE", "-newer": "CONFIG_FEATURE_FIND_NEWER",
		"-perm": "CONFIG_FEATURE_FIND_PERM", "-size": "CONFIG_FEATURE_FIND_SIZE", "-user": "CONFIG_FEATURE_FIND_USER",
		"-prune": "CONFIG_FEATURE_FIND_PRUNE", "-not": "CONFIG_FEATURE_FIND_NOT", "!": "CONFIG_FEATURE_FIND_NOT",
	},
	"tr":    {"-c": "CONFIG_FEATURE_TR_CLASSES"},
	"mount": {"-o": "CONFIG_FEATURE_MOUNT_FLAGS"},
}

// busyboxLongOptions are applets whose options are whole words (find's
// predicates), not clusters of letters.
var busyboxLongOptions = map[string]bool{"find": true}

// shellKeywords may come before a command on a line.
var shellKeywords = map[string]bool{"if": true, "then": true, "else": true, "elif": true, "do": true, "while": true, "until": true, "!": true, "exec": true, "time": true}

var shellSeparators = regexp.MustCompile("[|;&()`{}]")

func busyboxConfig(t *testing.T) map[string]bool {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "build", "busybox", "busybox.config"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	on := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if sym, ok := strings.CutSuffix(strings.TrimSpace(sc.Text()), "=y"); ok && !strings.HasPrefix(sym, "#") {
			on[sym] = true
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return on
}

// missingOptions returns, for one script line, each applet option the config
// doesn't build, as "applet option (SYMBOL)".
func missingOptions(line string, on map[string]bool) []string {
	if i := strings.Index(line, "#"); i == 0 || (i > 0 && line[i-1] == ' ') {
		line = line[:i]
	}
	var out []string
	for _, seg := range shellSeparators.Split(line, -1) {
		words := strings.Fields(strings.ReplaceAll(seg, `"`, " "))
		for len(words) > 0 && (shellKeywords[words[0]] || strings.Contains(words[0], "=")) {
			words = words[1:]
		}
		if len(words) == 0 {
			continue
		}
		applet := filepath.Base(words[0])
		opts, ok := busyboxGated[applet]
		if !ok {
			continue
		}
		for _, w := range words[1:] {
			if w == "--" {
				break
			}
			if !strings.HasPrefix(w, "-") && w != "!" {
				continue
			}
			var flags []string
			if busyboxLongOptions[applet] {
				flags = []string{w}
			} else {
				for _, c := range strings.TrimPrefix(w, "-") {
					flags = append(flags, "-"+string(c))
				}
			}
			for _, fl := range flags {
				if sym, ok := opts[fl]; ok && !on[sym] {
					out = append(out, applet+" "+fl+" ("+sym+")")
				}
			}
		}
	}
	return out
}

// shippedScripts are the shell scripts the root and the lab overlay ship.
func shippedScripts(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, dir := range []string{"..", filepath.Join("..", "..", "build", "lab", "overlay")} {
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return err
			}
			b, err := os.ReadFile(p) // #nosec G304 -- a file in this repository
			if err != nil {
				return err
			}
			if strings.HasPrefix(string(b), "#!/bin/sh") {
				out = append(out, p)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(out) == 0 {
		t.Fatal("no shipped shell scripts found")
	}
	return out
}

func TestShippedScriptsUseOnlyBuiltBusyboxOptions(t *testing.T) {
	on := busyboxConfig(t)
	for _, p := range shippedScripts(t) {
		b, err := os.ReadFile(p) // #nosec G304 -- a file in this repository
		if err != nil {
			t.Fatal(err)
		}
		for n, line := range strings.Split(string(b), "\n") {
			for _, m := range missingOptions(line, on) {
				t.Errorf("%s:%d uses %s, which busybox.config doesn't build", p, n+1, m)
			}
		}
	}
}

func TestTheCheckFindsAnOptionThatIsntBuilt(t *testing.T) {
	on := map[string]bool{"CONFIG_FEATURE_LS_FOLLOWLINKS": true}
	for line, want := range map[string]int{
		`slot="$(readlink -f "$product")"`:          1,
		`if ls -lL /x | grep -A2 y; then`:           1,
		`find /a -maxdepth 1 -type f -exec rm {} +`: 3,
		`# readlink -f in a comment`:                0,
		`echo readlink -f`:                          0,
		`ls -L /x`:                                  0,
	} {
		if got := missingOptions(line, on); len(got) != want {
			t.Errorf("%q: got %v, want %d", line, got, want)
		}
	}
}

// promptNeeds maps what a prompt may use to the busybox options ash needs
// to expand it (busybox 1.38's shell/Config.src and libbb/Config.src).
var promptNeeds = []struct {
	use  *regexp.Regexp
	syms []string
}{
	{regexp.MustCompile(`\$\(\(`), []string{"CONFIG_FEATURE_SH_MATH", "CONFIG_FEATURE_SH_MATH_64"}},
	{regexp.MustCompile(`\$[({]|\$[A-Za-z_]`), []string{"CONFIG_ASH_EXPAND_PRMT"}},
	{regexp.MustCompile(`\\[wWhHu$]`), []string{"CONFIG_FEATURE_EDITING", "CONFIG_FEATURE_EDITING_FANCY_PROMPT"}},
	{regexp.MustCompile(`\$\(date `), []string{"CONFIG_DATE"}},
}

func TestTheRootPromptUsesOnlyWhatBusyboxBuilds(t *testing.T) {
	on := busyboxConfig(t)
	for _, n := range promptNeeds {
		if !n.use.MatchString(elevated.Prompt) {
			continue
		}
		for _, sym := range n.syms {
			if !on[sym] {
				t.Errorf("the root shell's PS1 %q needs %s, which busybox.config doesn't build", elevated.Prompt, sym)
			}
		}
	}
	if !strings.Contains(elevated.Prompt, `\h`) {
		t.Errorf("the root shell's PS1 %q doesn't show the host name", elevated.Prompt)
	}
}
