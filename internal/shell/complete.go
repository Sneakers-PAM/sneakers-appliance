// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell

import (
	"bytes"
	"context"
	_ "embed"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// zonesFile is the canonical IANA time zone names (tzdata's
// zone1970.tab), one per line, for completing time-zone=.
//
//go:embed zones.txt
var zonesFile string

func zones() []string { return append([]string{"UTC"}, strings.Fields(zonesFile)...) }

// keyValues are the values the shell knows for a key: the time zones.
var keyValues = map[string]func() []string{"time-zone": zones}

// completeKeys offers the keys not given yet as "key=", and once a key's
// "=" is typed, the values the shell knows for it.
func completeKeys(keys []Key) func(context.Context, *Env, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(_ context.Context, _ *Env, args []string, partial string) ([]string, cobra.ShellCompDirective) {
		if name, v, ok := strings.Cut(partial, "="); ok {
			values := keyValues[name]
			if values == nil {
				return nil, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
			}
			var out []string
			for _, z := range values() {
				if strings.HasPrefix(z, v) {
					out = append(out, name+"="+z)
				}
			}
			return out, cobra.ShellCompDirectiveNoFileComp
		}
		var out []string
		for _, k := range keys {
			given := slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(a, k.Name+"=") })
			if !given {
				out = append(out, k.Name+"=\t"+k.Help)
			}
		}
		return out, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
	}
}

func completeMcp(_ context.Context, _ *Env, args []string, partial string) ([]string, cobra.ShellCompDirective) {
	switch len(args) {
	case 0:
		return []string{"off\tturn the MCP off", "on\tturn the MCP on"}, cobra.ShellCompDirectiveNoFileComp
	case 1:
		if strings.HasPrefix(partial, "machine-api=") {
			return []string{"machine-api=off", "machine-api=on"}, cobra.ShellCompDirectiveNoFileComp
		}
		return []string{"machine-api=\tset the machine API too"}, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
	}
	return nil, cobra.ShellCompDirectiveNoFileComp
}

// completeUpdates offers updates' two settings, then the channel's values
// or the repository's default.
func completeUpdates(_ context.Context, _ *Env, args []string, _ string) ([]string, cobra.ShellCompDirective) {
	switch {
	case len(args) == 0:
		return []string{"channel\tthe channel the GitHub source follows", "repo\ta lab build's test repository"}, cobra.ShellCompDirectiveNoFileComp
	case len(args) == 1 && args[0] == "channel":
		return []string{"default\tthis build's own", "rc\trelease candidates, and newer stable releases", "stable\tstable releases only"}, cobra.ShellCompDirectiveNoFileComp
	case len(args) == 1 && args[0] == "repo":
		return []string{"default\tthe build's own"}, cobra.ShellCompDirectiveNoFileComp
	}
	return nil, cobra.ShellCompDirectiveNoFileComp
}

// adminNames are the admins accessd lists, for --admin; nothing when it
// can't be asked.
func adminNames(ctx context.Context, e *Env) []string {
	if e.Backend == nil {
		return nil
	}
	res, err := e.Backend.Call(ctx, Request{Action: "admins.list"})
	if err != nil {
		return nil
	}
	rows, _ := res.Data.([]map[string]any)
	var out []string
	for _, r := range rows {
		if n, ok := r["name"].(string); ok && n != "" {
			out = append(out, n)
		}
	}
	return out
}

// Completions completes the last word of typed for session e with the
// command tree's own completion (cobra's __complete): the longest
// unambiguous extension, with a space after a word that's complete. It
// also returns the candidates for the word, which a second Tab lists.
// Only what the session may run is offered.
func Completions(e *Env, typed string) (string, []string) {
	words, err := Split(typed)
	if err != nil {
		return typed, nil
	}
	partial := ""
	if typed != "" && !strings.HasSuffix(typed, " ") && !strings.HasSuffix(typed, "\t") && len(words) > 0 {
		partial, words = words[len(words)-1], words[:len(words)-1]
	}
	cands, directive := complete(e, words, partial)
	if len(words) == 0 && strings.HasPrefix("exit", partial) {
		cands = append(cands, "exit")
		slices.Sort(cands)
	}
	if len(cands) == 0 {
		return typed, nil
	}
	common := cands[0]
	for _, c := range cands[1:] {
		common = commonPrefix(common, c)
	}
	if len(common) < len(partial) {
		return typed, cands
	}
	if len(cands) == 1 && directive&cobra.ShellCompDirectiveNoSpace == 0 {
		common += " "
	}
	return typed[:len(typed)-len(partial)] + common, cands
}

// complete runs cobra's completion for words and the partial last word.
func complete(e *Env, words []string, partial string) ([]string, cobra.ShellCompDirective) {
	var out bytes.Buffer
	session := *e
	session.Out, session.Err, session.In = io.Discard, io.Discard, strings.NewReader("")
	root := newRoot(context.Background(), &session)
	root.SetArgs(append(append([]string{cobra.ShellCompRequestCmd}, words...), partial))
	root.SetOut(&out)
	root.SetErr(io.Discard)
	if _, err := root.ExecuteC(); err != nil {
		return nil, cobra.ShellCompDirectiveError
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[len(lines)-1], ":") {
		return nil, cobra.ShellCompDirectiveError
	}
	d, err := strconv.Atoi(strings.TrimPrefix(lines[len(lines)-1], ":"))
	if err != nil || cobra.ShellCompDirective(d)&cobra.ShellCompDirectiveError != 0 {
		return nil, cobra.ShellCompDirectiveError
	}
	var cands []string
	for _, l := range lines[:len(lines)-1] {
		word, _, _ := strings.Cut(l, "\t")
		if word != "" && strings.HasPrefix(word, partial) && word != cobra.ShellCompRequestCmd && word != cobra.ShellCompNoDescRequestCmd {
			cands = append(cands, word)
		}
	}
	return cands, cobra.ShellCompDirective(d)
}
