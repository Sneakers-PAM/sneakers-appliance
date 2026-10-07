// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package dashboard

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/enrolment"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/enrol"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

// Deps are what the dashboard reads and drives.
type Deps struct {
	Chrome   consoleui.Chrome
	Custody  func(ctx context.Context) (keycustody.Protection, keycustody.Mode, error)
	Status   func(ctx context.Context) sources.StatusView
	Network  sources.Network
	HostKeys func() []sources.HostKey
	Slot     string
	Upgrades sources.Upgrades
	Platform sources.Platform
	// Shell runs the console commands, as the closed shell's console
	// origin.
	Shell  shell.Backend
	Access accessv1connect.AccessServiceClient
	Local  osadminv1connect.LocalServiceClient
	// Enrol is the enrolment window's, for Recover access.
	Enrol        enrolment.Deps
	MessagesFile string
	// Refresh is how often the status is read again; zero is 5 seconds.
	Refresh time.Duration
	Now     func() time.Time
	Logger  log.Logger
}

type console struct {
	u      *tui.UI
	d      Deps
	c      consoleui.Chrome
	data   Data
	loaded time.Time
}

// Run runs the console until ctx ends or the console's input does.
func Run(ctx context.Context, u *tui.UI, d Deps) error {
	if d.Refresh == 0 {
		d.Refresh = 5 * time.Second
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Logger == nil {
		d.Logger = log.Nop()
	}
	k := &console{u: u, d: d, c: d.Chrome}
	k.load(ctx)
	for {
		line, _, err := u.Ask(ctx, k.statusView(ctx))
		if err != nil {
			return err
		}
		if strings.TrimSpace(line) == "" {
			err = k.menu(ctx)
		} else {
			err = k.direct(ctx, line)
		}
		if err != nil {
			return err
		}
		k.load(ctx)
	}
}

// load reads everything the status view shows.
func (k *console) load(ctx context.Context) {
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	d := Data{Slot: k.d.Slot}
	if p, m, err := k.d.Custody(c); err == nil {
		k.c.Protection, k.c.Mode, k.c.Known = p, m, true
	} else {
		k.c.Known = false
		k.d.Logger.Warn("console: init's custody didn't answer", log.F("error", err.Error()))
	}
	d.Status = k.d.Status(c)
	if !k.d.Network.Installed() {
		d.NetErr = sources.NotInstalled{What: "The network service"}
	}
	if st := d.Status.Status; st != nil {
		k.c.Host = st.GetHostname()
		k.c.NTP = consoleui.NTPUnsynced
		if st.GetNtpSynced() {
			k.c.NTP = consoleui.NTPSynced
		}
		if d.NetErr != nil {
			k.c.NTP = consoleui.NTPUnknown
		}
	}
	d.HostKeys = k.d.HostKeys()
	d.Upgrade, d.UpgradeErr = k.d.Upgrades.Current(c)
	d.Platform, d.PlatformErr = k.d.Platform.State(c)
	k.data, k.loaded = d, time.Now()
}

// statusView redraws on every tick (the clock and a reset's countdown)
// and reads the status again every Refresh.
func (k *console) statusView(ctx context.Context) func() (tui.Page, bool) {
	return func() (tui.Page, bool) {
		if time.Since(k.loaded) >= k.d.Refresh {
			k.load(ctx)
		}
		if k.data.Upgrade.InProgress || (k.data.UpgradeErr == nil && k.data.Upgrade.Failed != "") {
			return MaintenancePage(k.c, k.data.Upgrade), false
		}
		return Page(k.c, k.data, k.d.Now()), false
	}
}

// entry is one menu entry and what it does.
type entry struct {
	Item
	run func(ctx context.Context) error
}

func (k *console) entries() []entry {
	var es []entry
	for _, info := range shell.Commands(shell.OriginConsole) {
		info := info
		es = append(es, entry{Item{Label: info.Path}, func(ctx context.Context) error { return k.command(ctx, info, "", false) }})
	}
	es = append(es,
		entry{Item{Label: "Recover access"}, k.recoverAccess},
		entry{Item{Label: "Recent messages"}, k.messages},
	)
	for i := range es {
		es[i].Key = strconv.Itoa(i + 1)
	}
	if fr := k.data.Status.Status.GetFactoryReset(); fr != nil {
		es = append(es, entry{Item{Key: "c", Label: "Cancel the factory reset"}, k.cancelReset})
	}
	return es
}

func (k *console) menu(ctx context.Context) error {
	errLine := ""
	for {
		es := k.entries()
		items := make([]Item, len(es))
		for i, e := range es {
			items[i] = e.Item
		}
		line, _, err := k.u.Ask(ctx, tui.Static(MenuPage(k.c, items, errLine)))
		if err != nil {
			return err
		}
		errLine = ""
		key := strings.ToLower(strings.TrimSpace(line))
		if key == "" || key == "0" {
			return nil
		}
		found := false
		for _, e := range es {
			if e.Key == key {
				found = true
				if err := e.run(ctx); err != nil {
					return err
				}
			}
		}
		if !found {
			errLine = fmt.Sprintf("%q isn't on the menu.", key)
		}
	}
}

// direct runs a command line typed at the status view.
func (k *console) direct(ctx context.Context, line string) error {
	if words, err := shell.Split(line); err == nil && len(words) > 0 && (words[0] == "help" || words[0] == "menu") {
		return k.menu(ctx)
	}
	for _, info := range shell.Commands(shell.OriginConsole) {
		if strings.HasPrefix(line+" ", info.Path+" ") {
			return k.command(ctx, info, strings.TrimSpace(strings.TrimPrefix(line, info.Path)), true)
		}
	}
	return k.transcript(ctx, line, nil, func(e *shell.Env) error { return shell.Run(ctx, e, line) })
}

// command runs one console command: what it takes first, then its
// transcript.
func (k *console) command(ctx context.Context, info shell.Info, args string, typed bool) error {
	var in io.Reader
	if info.Stdin {
		key, _, err := k.u.Ask(ctx, tui.Static(ArgsPage(k.c, info)))
		if err != nil {
			return err
		}
		if strings.TrimSpace(key) == "" {
			return nil
		}
		in = strings.NewReader(key + "\n")
	} else if !typed && (info.Args || len(info.Flags) > 0) {
		a, _, err := k.u.Ask(ctx, tui.Static(ArgsPage(k.c, info)))
		if err != nil {
			return err
		}
		args = strings.TrimSpace(a)
	}
	line := strings.TrimSpace(info.Path + " " + args)
	k.d.Logger.Info("console: command", log.F("command", info.Path))
	return k.transcript(ctx, line, in, func(e *shell.Env) error { return shell.Run(ctx, e, line) })
}

// liveIn is a command's standard input on the console: each read asks the
// screen for a typed line.
type liveIn struct {
	mu      sync.Mutex
	waiting bool
	lines   chan string
}

func (l *liveIn) Read(p []byte) (int, error) {
	l.mu.Lock()
	l.waiting = true
	l.mu.Unlock()
	line, ok := <-l.lines
	if !ok {
		return 0, io.EOF
	}
	return copy(p, line+"\n"), nil
}

func (l *liveIn) wants() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.waiting
}

func (l *liveIn) give(line string) {
	l.mu.Lock()
	l.waiting = false
	l.mu.Unlock()
	l.lines <- line
}

// out collects a command's output for its transcript.
type out struct {
	mu sync.Mutex
	b  strings.Builder
}

func (o *out) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.b.Write(p)
}

// lines are the full lines so far and the partial last one.
func (o *out) lines() ([]string, string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	s := sanitize(o.b.String())
	all := strings.Split(s, "\n")
	return all[:len(all)-1], all[len(all)-1]
}

// sanitize keeps a command's output to plain printable text, so nothing it
// prints can move the cursor or change the screen.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, s)
}

// transcript runs a command and shows what it prints; a line it reads is
// typed at the prompt, after its own question.
func (k *console) transcript(ctx context.Context, line string, in io.Reader, run func(e *shell.Env) error) error {
	o := &out{}
	live := &liveIn{lines: make(chan string)}
	if in == nil {
		in = live
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = run(&shell.Env{Origin: shell.OriginConsole, Backend: k.d.Shell, In: in, Out: o, Err: o})
	}()
	finished := false
	for {
		lineIn, typed, err := k.u.Ask(ctx, func() (tui.Page, bool) {
			select {
			case <-done:
				if !finished {
					finished = true
				}
			default:
			}
			lines, partial := o.lines()
			prompt := ""
			switch {
			case finished:
				if partial != "" {
					lines = append(lines, partial)
				}
				prompt = "> "
			case live.wants():
				prompt = partial
			default:
				if partial != "" {
					lines = append(lines, partial)
				}
			}
			return CommandPage(k.c, line, lines, prompt, finished), false
		})
		if err != nil {
			close(live.lines)
			return err
		}
		if !typed {
			continue
		}
		switch {
		case finished:
			return nil
		case live.wants():
			live.give(lineIn)
		}
	}
}

// recoverAccess is the console's Recover access: an owner's name, or a
// new one, then the enrolment window with the recovery hold.
func (k *console) recoverAccess(ctx context.Context) error {
	errLine := ""
	for {
		var owners []string
		existing := map[string]bool{}
		if l, err := k.d.Access.ListAdmins(ctx, connect.NewRequest(&accessv1.ListAdminsRequest{})); err == nil {
			for _, a := range l.Msg.GetAdmins() {
				existing[a.GetName()] = true
				if a.GetRole() == osadminv1.Role_ROLE_OWNER {
					owners = append(owners, a.GetName())
				}
			}
		} else if errLine == "" {
			errLine = "The admins can't be listed: " + consoleui.Describe(err)
		}
		line, _, err := k.u.Ask(ctx, tui.Static(RecoverPage(k.c, owners, errLine)))
		if err != nil {
			return err
		}
		name := strings.TrimSpace(line)
		if name == "" {
			return nil
		}
		if !existing[name] {
			if !access.ValidName(name) {
				errLine = fmt.Sprintf("%q can't be an admin name: use 2 to 31 lowercase letters, digits, _ or -, starting with a letter, and not a reserved name.", name)
				continue
			}
			if _, err := k.d.Access.AddAdmin(ctx, connect.NewRequest(&accessv1.AddAdminRequest{Name: name, Role: osadminv1.Role_ROLE_OWNER})); err != nil {
				errLine = consoleui.Describe(err)
				continue
			}
			k.d.Logger.Info("console: Recover access made a new owner", log.F("admin", name))
		}
		ed := k.d.Enrol
		ed.Page = func(title string, body []tui.Line, keys, prompt string) tui.Page {
			return k.c.Page(title, body, keys, prompt)
		}
		n, err := enrolment.Run(ctx, k.u, ed, name, true)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, tui.ErrClosed) {
				return err
			}
			errLine = consoleui.Describe(err)
			continue
		}
		k.d.Logger.Info("console: Recover access", log.F("admin", name), log.F("keys", n))
		if _, _, err := k.u.Ask(ctx, tui.Static(RecoverDonePage(k.c, name, n, k.d.Now().Add(enrol.RecoveryHold)))); err != nil {
			return err
		}
		return nil
	}
}

// messages shows the tail of the shared output.
func (k *console) messages(ctx context.Context) error {
	_, _, err := k.u.Ask(ctx, func() (tui.Page, bool) { return MessagesPage(k.c, tail(k.d.MessagesFile, 200)), false })
	return err
}

func tail(path string, n int) []string {
	f, err := os.Open(path) // #nosec G304 -- init's console log
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 1<<20)
	for sc.Scan() {
		lines = append(lines, sanitize(sc.Text()))
		if len(lines) > n {
			lines = lines[1:]
		}
	}
	return lines
}

// cancelReset stops a pending factory reset, as the console.
func (k *console) cancelReset(ctx context.Context) error {
	return k.transcript(ctx, "cancel the factory reset", nil, func(e *shell.Env) error {
		_, _ = fmt.Fprint(e.Out, "Type cancel to stop the factory reset: ")
		if line, _ := bufio.NewReader(e.In).ReadString('\n'); strings.TrimSpace(line) != "cancel" {
			_, _ = fmt.Fprintln(e.Out, "\nNot cancelled.")
			return nil
		}
		if _, err := k.d.Local.LocalCancelFactoryReset(ctx, connect.NewRequest(&osadminv1.LocalCancelFactoryResetRequest{Actor: "console"})); err != nil {
			_, _ = fmt.Fprintln(e.Out, "Not cancelled: "+consoleui.Describe(err))
			return err
		}
		_, _ = fmt.Fprintln(e.Out, "The factory reset is cancelled.")
		return nil
	})
}
