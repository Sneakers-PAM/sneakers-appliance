// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// Origin is where a command line came from.
type Origin string

// The two origins. Some commands exist in only one of them (Section 2.8).
const (
	OriginSSH     Origin = "ssh"
	OriginConsole Origin = "console"
)

// Request is one call to an appliance service.
type Request struct {
	// Action names the call, such as "keys.add".
	Action string
	Args   []string
	Flags  map[string]string
	// Stdin carries what the command read from standard input (a key for
	// keys add).
	Stdin []byte
}

// Result is what a call returns.
type Result struct {
	// Text is the human form.
	Text string
	// Data is the -o json form; nil prints Text as {"text": ...}.
	Data any
	// Stream, when set, is copied to standard output (logs export).
	Stream io.Reader
}

// Backend carries out requests. accessd's socket client is the real one;
// the shell decides nothing about roles itself.
type Backend interface {
	Call(ctx context.Context, r Request) (Result, error)
}

// Env is one shell session.
type Env struct {
	Origin  Origin
	Backend Backend
	In      io.Reader
	Out     io.Writer
	Err     io.Writer
	// RootShell relays the terminal to accessd's root-shell socket with a
	// ticket, until the root shell ends; nil (no terminal) refuses `shell`.
	RootShell func(ctx context.Context, socket, ticket string) error
}

type flagSpec struct {
	name, usage, def string
}

type spec struct {
	path    string // "keys add"
	use     string
	short   string
	action  string
	origins []Origin
	nargs   [2]int // min, max positional args; max -1 means any
	flags   []flagSpec
	stdin   bool
	// confirm is the word the admin types to confirm (reboot).
	confirm string
	// later marks the commands of specs 3 to 5, whose backends aren't on
	// the box yet.
	later bool
	run   func(ctx context.Context, e *Env, c *Command, args []string, flags map[string]string) (Result, error)
}

var both = []Origin{OriginSSH, OriginConsole}

// The commands of later specs (later: true) answer NOT_AVAILABLE until
// their services exist.
var specs = []spec{
	{path: "status", short: "Show the appliance status", action: "status", origins: both},
	{path: "network show", short: "Show the network settings", action: "network.show", origins: both},
	{path: "network set", use: "set key=value...", short: "Change network settings (reverts in 120 s unless confirmed)", action: "network.set", origins: both, nargs: [2]int{1, -1}, run: runNetworkSet},
	{path: "network confirm", use: "confirm <token>", short: "Keep a pending network change", action: "network.confirm", origins: both, nargs: [2]int{1, 1}},
	{path: "network allow-list reset", short: "Reset the management allow-list to the on-link default", action: "network.allowlist.reset", origins: []Origin{OriginConsole}, confirm: "reset"},
	{path: "keys list", short: "List login keys", action: "keys.list", origins: both, flags: []flagSpec{{"admin", "the admin (owners only; default yourself)", ""}}},
	{path: "admins list", short: "List the admins", action: "admins.list", origins: both},
	{path: "recovery-key add", short: "Add a recovery key, read from standard input (up to three)", action: "recovery.add", origins: []Origin{OriginConsole}, stdin: true, flags: []flagSpec{{"label", "a label such as \"offline safe\"", ""}}},
	{path: "setup recovery-key", short: "Set a recovery key during setup, read from standard input", action: "setup.recovery", origins: []Origin{OriginSSH}, stdin: true, flags: []flagSpec{{"label", "a label such as \"offline safe\"", ""}}},
	{path: "shell", short: "Open the root shell (root operators): a challenge, then the code :8443 gives for it", action: "rootshell.begin", origins: []Origin{OriginSSH}, run: runRootShell,
		flags: []flagSpec{{"reason", "why, for the audit log", ""}}},
	{path: "tls show", short: "Show the TLS certificates", action: "tls.show", origins: both, later: true},
	{path: "backup", use: "backup [...]", short: "Backups", action: "backup", origins: both, nargs: [2]int{0, -1}, later: true},
	{path: "restore", use: "restore [...]", short: "Restore from a backup", action: "restore", origins: both, nargs: [2]int{0, -1}, later: true},
	{path: "upgrade", use: "upgrade [...]", short: "Upgrades", action: "upgrade", origins: both, nargs: [2]int{0, -1}, later: true},
	{path: "mcp", use: "mcp [...]", short: "The MCP switch", action: "mcp", origins: both, nargs: [2]int{0, -1}, later: true},
	{path: "resources", use: "resources [...]", short: "Resource settings", action: "resources", origins: both, nargs: [2]int{0, -1}, later: true},
	{path: "logs export", short: "Stream the logs as an archive to standard output", action: "logs.export", origins: []Origin{OriginSSH}, later: true},
	{path: "support-bundle", short: "Stream a support bundle to standard output", action: "support.bundle", origins: []Origin{OriginSSH}, later: true},
	{path: "reboot", short: "Reboot the appliance", action: "power.reboot", origins: both, confirm: "reboot"},
	{path: "poweroff", short: "Shut the appliance down", action: "power.off", origins: both, confirm: "poweroff"},
}

// Command is a resolved command line.
type Command struct{ s *spec }

// Path is the command's words, such as "keys add".
func (c *Command) Path() string { return c.s.path }

// Action is the backend call it makes.
func (c *Command) Action() string { return c.s.action }

// Allowed reports whether the command exists in origin o.
func (c *Command) Allowed(o Origin) bool { return slices.Contains(c.s.origins, o) }

// Resolve finds the command words name, longest path first, or nil.
func Resolve(words []string) *Command {
	var best *spec
	for i := range specs {
		p := strings.Fields(specs[i].path)
		if len(p) <= len(words) && slices.Equal(p, words[:len(p)]) && (best == nil || len(p) > len(strings.Fields(best.path))) {
			best = &specs[i]
		}
	}
	if best == nil {
		return nil
	}
	return &Command{s: best}
}

// Actions are every backend call a command line can make. Nothing else
// leaves the shell.
func Actions() []string {
	out := []string{"rootshell.open", "network.confirm"}
	for _, s := range specs {
		if !slices.Contains(out, s.action) {
			out = append(out, s.action)
		}
	}
	return out
}

func laterAction(action string) bool {
	for _, s := range specs {
		if s.action == action {
			return s.later
		}
	}
	return false
}

// Names are the command paths offered in origin o, for help and completion.
func Names(o Origin) []string {
	var out []string
	for _, s := range specs {
		if slices.Contains(s.origins, o) {
			out = append(out, s.path)
		}
	}
	return out
}

// Info describes a command, for the console's menu.
type Info struct {
	Path, Use, Short string
	// Args: it takes positional arguments; Flags are its flag names.
	Args  bool
	Flags []string
	// Stdin: it reads a key from standard input.
	Stdin bool
	// Confirm is the word typed to confirm it.
	Confirm string
	// Later: its backend isn't in this release.
	Later bool
}

// Commands describes the commands offered in origin o, in the table's
// order.
func Commands(o Origin) []Info {
	var out []Info
	for _, s := range specs {
		if !slices.Contains(s.origins, o) {
			continue
		}
		i := Info{Path: s.path, Use: s.use, Short: s.short, Args: s.nargs[1] != 0, Stdin: s.stdin, Confirm: s.confirm, Later: s.later}
		if i.Use == "" {
			i.Use = s.path[strings.LastIndex(s.path, " ")+1:]
		}
		for _, f := range s.flags {
			i.Flags = append(i.Flags, f.name)
		}
		out = append(out, i)
	}
	return out
}

// Run executes one command line and reports errors on e.Err (or as JSON on
// e.Out with -o json). It returns the error for the exit status.
func Run(ctx context.Context, e *Env, line string) error {
	words, err := Split(line)
	if err != nil {
		report(e, false, err)
		return err
	}
	if len(words) == 0 {
		return nil
	}
	jsonOut := slices.Contains(words, "-o=json") || hasPair(words, "-o", "json") || hasPair(words, "--output", "json") || slices.Contains(words, "--output=json")
	root := newRoot(ctx, e)
	root.SetArgs(words)
	root.SetIn(e.In)
	root.SetOut(e.Out)
	root.SetErr(e.Err)
	if err := root.ExecuteContext(ctx); err != nil {
		var ran ranError
		_, coded := codes.Of(err)
		switch {
		case errors.As(err, &ran):
			err = ran.err
		case !coded:
			err = codes.Wrap(codes.ShellUnknown, err)
		}
		report(e, jsonOut, err)
		return err
	}
	return nil
}

func hasPair(words []string, k, v string) bool {
	for i := 0; i+1 < len(words); i++ {
		if words[i] == k && words[i+1] == v {
			return true
		}
	}
	return false
}

func newRoot(ctx context.Context, e *Env) *cobra.Command {
	root := &cobra.Command{
		Use:           "sneakers-shell",
		Short:         "The appliance's closed shell",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return codes.Wrap(codes.ShellParse, err) })
	root.PersistentFlags().StringP("output", "o", "text", "output format: text or json")
	groups := map[string]*cobra.Command{"": root}
	for i := range specs {
		s := &specs[i]
		parts := strings.Fields(s.path)
		parent := root
		for j := 0; j < len(parts)-1; j++ {
			key := strings.Join(parts[:j+1], " ")
			g, ok := groups[key]
			if !ok {
				g = &cobra.Command{Use: parts[j], Short: parts[j] + " commands"}
				groups[key] = g
				parent.AddCommand(g)
			}
			parent = g
		}
		parent.AddCommand(leaf(ctx, e, s, parts[len(parts)-1]))
	}
	return root
}

func leaf(ctx context.Context, e *Env, s *spec, name string) *cobra.Command {
	use := s.use
	if use == "" {
		use = name
	}
	cmd := &cobra.Command{
		Use:    use,
		Short:  s.short,
		Hidden: !slices.Contains(s.origins, e.Origin),
		Args: func(_ *cobra.Command, args []string) error {
			lo, hi := s.nargs[0], s.nargs[1]
			if len(args) < lo || hi >= 0 && len(args) > hi {
				return codes.New(codes.ShellParse, "%s takes %s", s.path, argCount(lo, hi))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			c := &Command{s: s}
			if !c.Allowed(e.Origin) {
				return codes.New(codes.AccessForbidden, "%s isn't available over %s", s.path, e.Origin)
			}
			flags := map[string]string{}
			for _, f := range s.flags {
				v, _ := cmd.Flags().GetString(f.name)
				if v != "" {
					flags[f.name] = v
				}
			}
			if s.confirm != "" && !typedConfirm(e, s.confirm) {
				return codes.New(codes.AccessForbidden, "not confirmed; type %s to confirm", s.confirm)
			}
			var (
				res Result
				err error
			)
			if s.run != nil {
				res, err = s.run(ctx, e, c, args, flags)
			} else {
				req := Request{Action: s.action, Args: args, Flags: flags}
				if s.stdin {
					if req.Stdin, err = readStdin(e.In); err != nil {
						return err
					}
				}
				res, err = e.Backend.Call(ctx, req)
			}
			if err != nil {
				return ranError{err}
			}
			out, _ := cmd.Flags().GetString("output")
			return emit(e, out == "json", res)
		},
	}
	for _, f := range s.flags {
		cmd.Flags().String(f.name, f.def, f.usage)
	}
	return cmd
}

func argCount(lo, hi int) string {
	switch {
	case hi < 0:
		return fmt.Sprintf("at least %d argument(s)", lo)
	case lo == hi:
		return fmt.Sprintf("%d argument(s)", lo)
	default:
		return fmt.Sprintf("%d to %d arguments", lo, hi)
	}
}

// maxStdin bounds what a command reads from standard input (a key, a short
// list of keys).
const maxStdin = 64 * 1024

func readStdin(in io.Reader) ([]byte, error) {
	if in == nil {
		return nil, codes.New(codes.ShellParse, "this command reads from standard input; pipe the key into it")
	}
	b, err := io.ReadAll(io.LimitReader(in, maxStdin+1))
	if err != nil {
		return nil, fmt.Errorf("reading standard input: %w", err)
	}
	if len(b) > maxStdin {
		return nil, codes.New(codes.ShellParse, "standard input is longer than %d bytes", maxStdin)
	}
	return b, nil
}

func readLine(in io.Reader) string {
	if in == nil {
		return ""
	}
	line, _ := bufio.NewReader(in).ReadString('\n')
	return strings.TrimSpace(line)
}

func typedConfirm(e *Env, word string) bool {
	_, _ = fmt.Fprintf(e.Out, "Type %s to confirm: ", word)
	return readLine(e.In) == word
}

func yes(e *Env, prompt string) bool {
	_, _ = fmt.Fprintf(e.Out, "%s [y/N] ", prompt)
	a := strings.ToLower(readLine(e.In))
	return a == "y" || a == "yes"
}

func runNetworkSet(ctx context.Context, e *Env, _ *Command, args []string, flags map[string]string) (Result, error) {
	res, err := e.Backend.Call(ctx, Request{Action: "network.set", Args: args, Flags: flags})
	if err != nil {
		return Result{}, err
	}
	data, _ := res.Data.(map[string]string)
	token := data["token"]
	if token == "" {
		return res, nil
	}
	_, _ = fmt.Fprintln(e.Out, res.Text)
	if !yes(e, "Keep the new settings? They revert in 120 seconds otherwise.") {
		return Result{Text: fmt.Sprintf("Not kept; the change reverts on its own. To keep it, run: network confirm %s", token)}, nil
	}
	return e.Backend.Call(ctx, Request{Action: "network.confirm", Args: []string{token}})
}

// runRootShell asks for a challenge, reads the code the operator got for it
// on :8443, trades both for a ticket and relays the terminal to the root
// shell until it ends. A wrong code may be typed again until the challenge
// closes.
func runRootShell(ctx context.Context, e *Env, _ *Command, _ []string, flags map[string]string) (Result, error) {
	if e.RootShell == nil {
		return Result{}, codes.New(codes.AccessForbidden, "the root shell needs a terminal: log in with ssh -t, or without a command")
	}
	res, err := e.Backend.Call(ctx, Request{Action: "rootshell.begin", Flags: flags})
	if err != nil {
		return Result{}, err
	}
	data, _ := res.Data.(map[string]string)
	challenge := data["challenge"]
	_, _ = fmt.Fprintln(e.Out, res.Text)
	lines := bufio.NewReader(e.In)
	for {
		_, _ = fmt.Fprint(e.Out, "Code: ")
		line, _ := lines.ReadString('\n')
		code := strings.TrimSpace(line)
		if code == "" {
			return Result{Text: "No code typed; the challenge stays open until it expires."}, nil
		}
		opened, err := e.Backend.Call(ctx, Request{Action: "rootshell.open", Args: []string{challenge, code}})
		if codes.Is(err, codes.RootCode) {
			_, _ = fmt.Fprintln(e.Out, codes.Describe(err))
			continue
		}
		if err != nil {
			return Result{}, err
		}
		od, _ := opened.Data.(map[string]string)
		if err := e.RootShell(ctx, od["socket"], od["ticket"]); err != nil {
			return Result{}, err
		}
		return Result{Text: "The root shell ended; back in the menu."}, nil
	}
}

// waitForApproval polls request id until an owner approves it (then
// prints its certificate), denies it or it expires. A status the shell
// can't read ends the wait with the request's own result.

func emit(e *Env, asJSON bool, r Result) error {
	if r.Stream != nil {
		_, err := io.Copy(e.Out, r.Stream)
		return err
	}
	if asJSON {
		data := r.Data
		if data == nil {
			data = map[string]string{"text": r.Text}
		}
		enc := json.NewEncoder(e.Out)
		enc.SetIndent("", "  ")
		return enc.Encode(data)
	}
	if r.Text != "" {
		_, err := fmt.Fprintln(e.Out, strings.TrimRight(r.Text, "\n"))
		return err
	}
	return nil
}

type jsonError struct {
	Error struct {
		Code    string `json:"code,omitempty"`
		Number  int    `json:"number,omitempty"`
		Message string `json:"message"`
	} `json:"error"`
}

func report(e *Env, asJSON bool, err error) {
	if asJSON {
		var j jsonError
		if c, ok := codes.Of(err); ok {
			j.Error.Code, j.Error.Number = codes.Symbol(c), c
		}
		j.Error.Message = codes.Describe(err)
		_ = json.NewEncoder(e.Out).Encode(j)
		return
	}
	_, _ = fmt.Fprintln(e.Err, codes.Describe(err))
}

// ranError marks an error a command returned, as opposed to one from
// parsing the line, so an uncoded refusal isn't reported as an unknown
// command.
type ranError struct{ err error }

func (e ranError) Error() string { return e.err.Error() }
func (e ranError) Unwrap() error { return e.err }

// ErrUnavailable is what a backend returns when accessd doesn't answer.
var ErrUnavailable = codes.Wrap(codes.NotAvailable, errors.New(accessapi.Unavailable))
