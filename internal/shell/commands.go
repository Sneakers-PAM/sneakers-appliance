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
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productinfo"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
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
	// Product is the installed product; its commands are offered under its
	// name only while one is installed.
	Product productinfo.Info
	// Values are the values the product exposes to this session's role,
	// each a command in the product's section.
	Values []Value
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
	// product marks a product's command: offered as "<product> <path>",
	// and only while a product is installed. The base shell never names
	// one.
	product bool
	// long and example are the command's help; {product} in an example
	// is the installed product's name. keys are the key=value settings
	// it takes, listed in its help from the same table its parser reads.
	long, example string
	keys          []Key
	run           func(ctx context.Context, e *Env, c *Command, args []string, flags map[string]string) (Result, error)
}

var both = []Origin{OriginSSH, OriginConsole}

// The commands of later specs (later: true) answer NOT_AVAILABLE until
// their services exist.
var specs = []spec{
	{path: "status", short: "Show the appliance status", action: "status", origins: both,
		long:    "Shows the host name, the version (and any staged one), the phase, the disk protection, the management addresses, NTP and the health of each service, with any warnings. While the appliance services are down it shows the last status they kept, with its time.",
		example: "  status\n  status -o json"},
	{path: "network show", short: "Show the network settings", action: "network.show", origins: both,
		long:    "Shows the host name, the management addresses, DNS servers and search domains, NTP servers, the management allow-list, the time zone and the HTTPS proxy.",
		example: "  network show\n  network show -o json"},
	{path: "network set", use: "set key=value...", short: "Change network settings (reverts in 120 s unless confirmed)", action: "network.set", origins: both, nargs: [2]int{0, -1}, keys: networkKeys, run: runNetworkSet,
		long:    "Changes the settings the keys name, on top of the current ones; the others stay as they are. The change is applied at once and reverts after 120 seconds unless it's kept: the command asks, or run network confirm with the token it prints. Owners only. With no arguments, or ?, it lists the keys. The interfaces' addresses are set on :8443 or the console's network screen.",
		example: "  network set ?\n  network set dns=192.0.2.53,192.0.2.54 search=sneakers.example.org\n  network set time-zone=America/New_York\n  network set https-proxy="},
	{path: "network confirm", use: "confirm <token>", short: "Keep a pending network change", action: "network.confirm", origins: both, nargs: [2]int{1, 1},
		long:    "Keeps the network change the token names, so it doesn't revert. network set and network allow-list reset print the token.",
		example: "  network confirm 7K2Q-MX4D"},
	{path: "network allow-list reset", short: "Reset the management allow-list to the on-link default", action: "network.allowlist.reset", origins: []Origin{OriginConsole}, confirm: "reset",
		long:    "Sets the management allow-list back to the subnets the box is on, for when a wrong list locks SSH and :8443 out. Console only; type reset to confirm. It reverts in 120 seconds unless kept with network confirm.",
		example: "  network allow-list reset"},
	{path: "keys list", short: "List login keys", action: "keys.list", origins: both, flags: []flagSpec{{"admin", "the admin (owners only; default yourself)", ""}},
		long:    "Lists an admin's SSH login keys: fingerprint, type and comment. Without --admin it lists your own; an owner may name any admin. Keys are issued on :8443.",
		example: "  keys list\n  keys list --admin alice"},
	{path: "admins list", short: "List the admins", action: "admins.list", origins: both,
		long:    "Lists the admins with their role (owner or admin) and how many login keys each has. Admins are added and removed on :8443.",
		example: "  admins list\n  admins list -o json"},
	{path: "recovery-key add", short: "Add a recovery key, read from standard input (up to three)", action: "recovery.add", origins: []Origin{OriginConsole}, stdin: true, flags: []flagSpec{{"label", "a label such as \"offline safe\"", ""}},
		long:    "Adds a recovery key, an SSH public key read from standard input, and writes a new escrow file. Console only; a box keeps up to three.",
		example: "  recovery-key add --label \"offline safe\""},
	{path: "setup recovery-key", short: "Set a recovery key during setup, read from standard input", action: "setup.recovery", origins: []Origin{OriginSSH}, stdin: true, flags: []flagSpec{{"label", "a label such as \"offline safe\"", ""}},
		long:    "Sets the first recovery key during setup: an SSH public key read from standard input. Over SSH, first boot only; it writes a new escrow file.",
		example: "  ssh -t admin@box1.sneakers.example.org setup recovery-key --label safe < recovery.pub"},
	{path: "shell", short: "Open the root shell (root operators): a challenge, then the code :8443 gives for it", action: "rootshell.begin", origins: []Origin{OriginSSH}, run: runRootShell,
		flags:   []flagSpec{{"reason", "why, for the audit log", ""}},
		long:    "Opens the root shell, for root operators. It prints a challenge; paste it on the Root shell page on :8443, give a fresh authenticator code there, and type the code that page gives you here. The session is time-boxed, recorded and audited. Needs a terminal (ssh -t).",
		example: "  shell --reason \"check the k0s pods\""},
	{path: "tls show", short: "Show the TLS certificates", action: "tls.show", origins: both, later: true,
		long:    "Shows the TLS certificates the box serves. Not available in this release.",
		example: "  tls show"},
	{path: "backup", use: "backup [...]", short: "Backups", action: "backup", origins: both, nargs: [2]int{0, -1}, later: true,
		long:    "Makes and lists backups. Not available in this release.",
		example: "  backup"},
	{path: "restore", use: "restore [...]", short: "Restore from a backup", action: "restore", origins: both, nargs: [2]int{0, -1}, later: true,
		long:    "Restores the box from a backup. Not available in this release.",
		example: "  restore"},
	{path: "upgrade", use: "upgrade [...]", short: "Upgrades", action: "upgrade", origins: both, nargs: [2]int{0, -1}, later: true,
		long:    "Stages and applies updates from the shell. Not available in this release; updates are done on :8443.",
		example: "  upgrade status"},
	{path: "mcp", use: "mcp [on|off] [machine-api=on|off]", short: "Show or set the MCP switch, the one the MCP card on :8443 sets", action: "mcp.set", origins: both, nargs: [2]int{0, 2}, product: true, run: runMcp,
		long:    "Without arguments it shows the installed product's MCP switch and its machine API switch. on or off sets the MCP switch; the machine API keeps its setting unless the line names it with machine-api=on or machine-api=off. The switches are the ones the product declares, the same ones the MCP card on :8443 sets, under the same role and audit.",
		example: "  {product} mcp\n  {product} mcp on\n  {product} mcp off machine-api=off"},
	{path: "resources", use: "resources [...]", short: "Resource settings", action: "resources", origins: both, nargs: [2]int{0, -1}, later: true,
		long:    "Shows and sets the resources the product may use. Not available in this release.",
		example: "  resources"},
	{path: "logs export", short: "Stream the logs as an archive to standard output", action: "logs.export", origins: []Origin{OriginSSH}, later: true,
		long:    "Streams the box's logs as an archive to standard output, to save on your side. Over SSH only. Not available in this release.",
		example: "  ssh admin@box1.sneakers.example.org logs export > logs.tar"},
	{path: "support-bundle", short: "Stream a support bundle to standard output", action: "support.bundle", origins: []Origin{OriginSSH}, later: true,
		long:    "Streams a support bundle (status, logs and settings, with no secrets) to standard output. Over SSH only. Not available in this release.",
		example: "  ssh admin@box1.sneakers.example.org support-bundle > support.tar"},
	{path: "reboot", short: "Reboot the appliance", action: "power.reboot", origins: both, confirm: "reboot",
		long:    "Reboots the box gracefully: the services stop first. Type reboot to confirm.",
		example: "  reboot"},
	{path: "poweroff", short: "Shut the appliance down", action: "power.off", origins: both, confirm: "poweroff",
		long:    "Shuts the box down gracefully: the services stop first. Type poweroff to confirm.",
		example: "  poweroff"},
}

// Value is one value the installed product exposes to this session (its
// product.yaml's exposed_values for the session's role): a command in the
// product's section.
type Value struct {
	Name, Label string
}

// specsFor is the command table with p installed: the base's and p's
// own commands, then one per value p exposes to this session.
func specsFor(p productinfo.Info, values []Value) []spec {
	if !p.Present() || len(values) == 0 {
		return specs
	}
	out := slices.Clone(specs)
	for _, v := range values {
		short := v.Label
		if short == "" {
			short = p.Title + "'s " + v.Name
		}
		out = append(out, spec{path: v.Name, short: short + " (shown to the roles the product names)", action: "product.value", origins: []Origin{OriginSSH}, product: true, run: runValue(v.Name),
			long:    "Shows " + short + ", a value the installed product exposes to your role, with the link that takes it. A one-time value is removed once it has been used; after that this says so. Over SSH only.",
			example: "  {product} " + v.Name})
	}
	return out
}

// runValue reads one exposed value; the name is fixed by the command, never
// typed.
func runValue(name string) func(ctx context.Context, e *Env, _ *Command, _ []string, _ map[string]string) (Result, error) {
	return func(ctx context.Context, e *Env, _ *Command, _ []string, _ map[string]string) (Result, error) {
		return e.Backend.Call(ctx, Request{Action: "product.value", Args: []string{name}})
	}
}

// ValuesFor are the values spec exposes to role (owner or admin).
func ValuesFor(spec productspec.Spec, role string) []Value {
	var out []Value
	for _, v := range spec.ExposedValues {
		if v.Allows(role) {
			out = append(out, Value{Name: v.Name, Label: v.Label})
		}
	}
	return out
}

// Command is a resolved command line.
type Command struct{ s *spec }

// Path is the command's words, such as "keys add".
func (c *Command) Path() string { return c.s.path }

// Action is the backend call it makes.
func (c *Command) Action() string { return c.s.action }

// Allowed reports whether the command exists in origin o.
func (c *Command) Allowed(o Origin) bool { return slices.Contains(c.s.origins, o) }

// Resolve finds the base command words name, longest path first, or nil.
func Resolve(words []string) *Command {
	var best *spec
	for i := range specs {
		if specs[i].product {
			continue
		}
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
	out := []string{"rootshell.open", "network.confirm", "product.value", "mcp.show"}
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

// Names are the base command paths offered in origin o, for help and
// completion.
func Names(o Origin) []string { return NamesFor(o, productinfo.Info{}) }

// NamesFor are the command paths offered in origin o with product p
// installed: the base's, then p's own under its name.
// values are the product's exposed values this session may read.
func NamesFor(o Origin, p productinfo.Info, values ...Value) []string {
	var out []string
	for _, s := range specsFor(p, values) {
		if !slices.Contains(s.origins, o) {
			continue
		}
		switch {
		case !s.product:
			out = append(out, s.path)
		case p.Present():
			out = append(out, p.Name+" "+s.path)
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

// Commands describes the base commands offered in origin o, in the
// table's order.
func Commands(o Origin) []Info {
	var out []Info
	for _, s := range specs {
		if s.product || !slices.Contains(s.origins, o) {
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
		Long:          "The appliance's closed shell: the commands below, nothing else. help <command> shows a command's purpose, what it takes and an example; -o json prints a result, or an error, as JSON.",
		Example:       "  help\n  help network set\n  status -o json",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return codes.Wrap(codes.ShellParse, err) })
	root.PersistentFlags().StringP("output", "o", "text", "output format: text or json")
	root.AddGroup(&cobra.Group{ID: groupBase, Title: "Appliance commands:"})
	root.SetHelpCommandGroupID(groupBase)
	groups := map[string]*cobra.Command{"": root}
	if e.Product.Present() {
		root.AddGroup(&cobra.Group{ID: groupProduct, Title: e.Product.Title + " commands (the installed product):"})
		g := &cobra.Command{Use: e.Product.Name, Short: e.Product.Title + " commands", GroupID: groupProduct,
			Long: "The commands of " + e.Product.Title + ", the installed product. They're offered only while it's installed."}
		groups[e.Product.Name] = g
		root.AddCommand(g)
	}
	all := specsFor(e.Product, e.Values)
	for i := range all {
		s := &all[i]
		path := s.path
		if s.product {
			if !e.Product.Present() {
				continue
			}
			path = e.Product.Name + " " + path
		}
		parts := strings.Fields(path)
		parent := root
		for j := 0; j < len(parts)-1; j++ {
			key := strings.Join(parts[:j+1], " ")
			g, ok := groups[key]
			if !ok {
				doc := groupDoc[key]
				if doc[0] == "" {
					doc[0] = parts[j] + " commands"
				}
				g = &cobra.Command{Use: parts[j], Short: doc[0], Long: doc[1]}
				if j == 0 {
					g.GroupID = groupBase
				}
				groups[key] = g
				parent.AddCommand(g)
			}
			parent = g
		}
		c := leaf(ctx, e, s, parts[len(parts)-1])
		if parent == root {
			c.GroupID = groupBase
		}
		parent.AddCommand(c)
	}
	root.InitDefaultHelpCmd()
	for _, c := range root.Commands() {
		if c.Name() == "help" {
			c.Long = "Shows the commands, or one command's purpose, usage, flags, keys and an example."
			c.Example = "  help\n  help network set\n  help keys list"
		}
	}
	documentGroups(root)
	return root
}

// groupDoc is each command group's short and long description; a
// group's example is its commands' first examples.
var groupDoc = map[string][2]string{
	"network":            {"Network settings", "The network settings: show them, change them (with an automatic revert) and keep a change."},
	"network allow-list": {"The management allow-list", "The management allow-list, the networks that may reach SSH and :8443."},
	"keys":               {"Login keys", "The admins' SSH login keys. Keys are issued on :8443."},
	"admins":             {"Admins", "The admins of this box. They're added and removed on :8443."},
	"recovery-key":       {"Recovery keys", "The recovery keys, which open the box when no admin can."},
	"setup":              {"First boot setup", "The steps of first boot that are done over SSH."},
	"tls":                {"TLS certificates", "The TLS certificates the box serves."},
	"logs":               {"Logs", "The box's logs."},
}

func documentGroups(c *cobra.Command) {
	for _, sub := range c.Commands() {
		documentGroups(sub)
	}
	if c.Example != "" || !c.HasSubCommands() {
		return
	}
	var ex []string
	for _, sub := range c.Commands() {
		if first, _, _ := strings.Cut(sub.Example, "\n"); first != "" && !sub.Hidden {
			ex = append(ex, first)
		}
	}
	if len(ex) == 0 {
		for _, sub := range c.Commands() {
			if first, _, _ := strings.Cut(sub.Example, "\n"); first != "" {
				ex = append(ex, first)
			}
		}
	}
	c.Example = strings.Join(ex, "\n")
	if c.Long == "" {
		c.Long = c.Short + "."
	}
}

// Tree is the command tree a session in origin o sees with product p
// installed and values exposed to its role, for the docs and the tests.
func Tree(o Origin, p productinfo.Info, values ...Value) *cobra.Command {
	return newRoot(context.Background(), &Env{Origin: o, Product: p, Values: values})
}

// The help's sections: the base appliance's commands, then the installed
// product's.
const (
	groupBase    = "base"
	groupProduct = "product"
)

func leaf(ctx context.Context, e *Env, s *spec, name string) *cobra.Command {
	use := s.use
	if use == "" {
		use = name
	}
	long := s.long
	if len(s.keys) > 0 {
		long += "\n\nKeys:\n" + strings.TrimRight(keyList(s.keys), "\n")
	}
	cmd := &cobra.Command{
		Use:     use,
		Short:   s.short,
		Long:    long,
		Example: strings.ReplaceAll(s.example, "{product}", e.Product.Name),
		Hidden:  !slices.Contains(s.origins, e.Origin),
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

// asker is the interactive terminal, which reads a line with a prompt of
// its own.
type asker interface {
	AskLine(prompt string) (string, error)
}

// ask prints prompt and reads one line: on the interactive terminal as
// its own prompt, so the answer ends the line and the menu's prompt comes
// back on the next one.
func ask(e *Env, prompt string) string {
	if a, ok := e.In.(asker); ok {
		line, _ := a.AskLine(prompt)
		return strings.TrimSpace(line)
	}
	_, _ = fmt.Fprint(e.Out, prompt)
	return readLine(e.In)
}

func typedConfirm(e *Env, word string) bool {
	return ask(e, fmt.Sprintf("Type %s to confirm: ", word)) == word
}

func yes(e *Env, prompt string) bool {
	a := strings.ToLower(ask(e, prompt+" [y/N] "))
	return a == "y" || a == "yes"
}

func runNetworkSet(ctx context.Context, e *Env, _ *Command, args []string, flags map[string]string) (Result, error) {
	if len(args) == 0 || len(args) == 1 && args[0] == "?" {
		return Result{Text: "network set takes key=value pairs, applied on top of the current settings:\n\n" + keyList(networkKeys) + "\nThe interfaces' addresses are set on :8443 or the console's network screen.", Data: keyData(networkKeys)}, nil
	}
	if _, err := parseKeys("network set", networkKeys, args); err != nil {
		return Result{}, err
	}
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

// runMcp shows the product's MCP switch, or sets it. The machine API
// switch keeps its current setting unless the line names it.
func runMcp(ctx context.Context, e *Env, _ *Command, args []string, _ map[string]string) (Result, error) {
	if len(args) == 0 {
		return e.Backend.Call(ctx, Request{Action: "mcp.show"})
	}
	on, ok := onOff(args[0])
	if !ok {
		return Result{}, codes.New(codes.ShellParse, "mcp takes on or off, not %q", Printable(args[0]))
	}
	api := ""
	if len(args) == 2 {
		k, v, _ := strings.Cut(args[1], "=")
		if k != "machine-api" {
			return Result{}, codes.New(codes.ShellParse, "mcp takes machine-api=on|off after on or off, not %q", Printable(args[1]))
		}
		if _, ok := onOff(v); !ok {
			return Result{}, codes.New(codes.ShellParse, "machine-api is on or off, not %q", Printable(v))
		}
		api = v
	}
	return e.Backend.Call(ctx, Request{Action: "mcp.set", Args: []string{map[bool]string{true: "on", false: "off"}[on]}, Flags: map[string]string{"machine-api": api}})
}

func onOff(v string) (bool, bool) {
	switch v {
	case "on":
		return true, true
	case "off":
		return false, true
	}
	return false, false
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
	var lines *bufio.Reader
	readCode := func() string {
		if a, ok := e.In.(asker); ok {
			line, _ := a.AskLine("Code: ")
			return strings.TrimSpace(line)
		}
		if lines == nil {
			lines = bufio.NewReader(e.In)
		}
		_, _ = fmt.Fprint(e.Out, "Code: ")
		line, _ := lines.ReadString('\n')
		return strings.TrimSpace(line)
	}
	for {
		code := readCode()
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
