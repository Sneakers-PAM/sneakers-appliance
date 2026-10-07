// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package enrolment

import (
	"context"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
)

// Deps are what the window's screens use.
type Deps struct {
	// Window is accessd's EnrolmentService, called as the console (root).
	Window accessv1connect.EnrolmentServiceClient
	// Fetch reads a published key list over https.
	Fetch func(ctx context.Context, url string) (access.Fetched, error)
	// Addresses are the management addresses ssh enrol@ connects to.
	Addresses func(ctx context.Context) ([]string, error)
	// SSH says why ssh enrol@ can't connect; nil when sshd runs.
	SSH func(ctx context.Context) error
	// Opened, when set, runs once the first window is open (its host keys
	// made): first boot opens port 22 and starts sshd there.
	Opened func(ctx context.Context)
	Page   PageFunc
	Now    func() time.Time
}

func waiting(w *accessv1.Enrolment) *accessv1.EnrolmentKey {
	for _, k := range w.GetKeys() {
		if k.GetState() == "waiting" {
			return k
		}
	}
	return nil
}

func accepted(w *accessv1.Enrolment) int {
	n := 0
	for _, k := range w.GetKeys() {
		if k.GetState() == "accepted" {
			n++
		}
	}
	return n
}

// Run opens a window for admin's keys (recovery: the console's Recover
// access) and runs it until Done, with at least one key enrolled. It
// returns how many keys were enrolled.
func Run(ctx context.Context, u *tui.UI, d Deps, admin string, recovery bool) (int, error) {
	if d.Now == nil {
		d.Now = time.Now
	}
	open := func() (*accessv1.Enrolment, error) {
		r, err := d.Window.OpenEnrolment(ctx, connect.NewRequest(&accessv1.OpenEnrolmentRequest{Admin: admin, Recovery: recovery}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetEnrolment(), nil
	}
	get := func() (*accessv1.Enrolment, error) {
		c, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		r, err := d.Window.GetEnrolment(c, connect.NewRequest(&accessv1.GetEnrolmentRequest{}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetEnrolment(), nil
	}
	w, err := open()
	if err != nil {
		return 0, err
	}
	if d.Opened != nil {
		d.Opened(ctx)
	}
	enrolled := 0
	var note, errLine string
	for {
		if !w.GetOpen() {
			if _, _, err := u.Ask(ctx, tui.Static(ClosedPage(d.Page, w))); err != nil {
				return enrolled, err
			}
			nw, err := open()
			if err != nil {
				return enrolled, err
			}
			w, note = nw, ""
			continue
		}
		if k := waiting(w); k != nil {
			line, _, err := u.Ask(ctx, tui.Static(OfferedPage(d.Page, w, k, errLine)))
			if err != nil {
				return enrolled, err
			}
			errLine = ""
			switch strings.ToLower(strings.TrimSpace(line)) {
			case "yes":
				if _, err := d.Window.AcceptEnrolmentKey(ctx, connect.NewRequest(&accessv1.AcceptEnrolmentKeyRequest{Id: k.GetId(), Confirm: "yes"})); err != nil {
					errLine = consoleui.Describe(err)
				} else {
					enrolled++
				}
			case "no":
				if _, err := d.Window.RejectEnrolmentKey(ctx, connect.NewRequest(&accessv1.RejectEnrolmentKeyRequest{Id: k.GetId()})); err != nil {
					errLine = consoleui.Describe(err)
				}
			default:
				errLine = "Type yes to store the key, or no to refuse it."
			}
			if nw, err := get(); err == nil {
				w = nw
			}
			continue
		}
		addrs, addrErr := d.Addresses(ctx)
		sshErr := d.SSH(ctx)
		code := w.GetCode()
		line, typed, err := u.Ask(ctx, func() (tui.Page, bool) {
			if nw, err := get(); err == nil {
				if nw.GetOpen() && nw.GetCode() != code {
					note, code = "Three wrong codes closed the window; this is its new code.", nw.GetCode()
				}
				w = nw
			}
			if !w.GetOpen() || waiting(w) != nil {
				return tui.Page{}, true
			}
			return WaitingPage(d.Page, Waiting{W: w, Addresses: addrs, AddrErr: addrErr, SSHErr: sshErr, Note: note, Err: errLine}, d.Now()), false
		})
		if err != nil {
			return enrolled, err
		}
		if !typed {
			continue
		}
		errLine = ""
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "t":
			if err := typeKey(ctx, u, d, w); err != nil {
				return enrolled, err
			}
		case "f":
			if err := fetch(ctx, u, d, w); err != nil {
				return enrolled, err
			}
		case "d":
			if accepted(w) == 0 {
				errLine = "Enrol at least one key first."
				continue
			}
			if _, err := d.Window.CloseEnrolment(ctx, connect.NewRequest(&accessv1.CloseEnrolmentRequest{})); err != nil {
				errLine = consoleui.Describe(err)
				continue
			}
			return enrolled, nil
		case "":
		default:
			errLine = fmt.Sprintf("%q isn't one of the keys below.", strings.TrimSpace(line))
		}
		if nw, err := get(); err == nil {
			w = nw
		}
	}
}

func typeKey(ctx context.Context, u *tui.UI, d Deps, w *accessv1.Enrolment) error {
	errLine := ""
	for {
		line, _, err := u.Ask(ctx, tui.Static(TypePage(d.Page, w, errLine)))
		if err != nil {
			return err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return nil
		}
		if _, err := d.Window.OfferEnrolmentKey(ctx, connect.NewRequest(&accessv1.OfferEnrolmentKeyRequest{PublicKey: line, Via: access.ViaTyped})); err != nil {
			errLine = consoleui.Describe(err)
			continue
		}
		return nil
	}
}

func fetch(ctx context.Context, u *tui.UI, d Deps, w *accessv1.Enrolment) error {
	line, _, err := u.Ask(ctx, tui.Static(URLPage(d.Page, w, "")))
	if err != nil {
		return err
	}
	url := strings.TrimSpace(line)
	if url == "" {
		return nil
	}
	u.Show(FetchingPage(d.Page, w, url))
	f, err := d.Fetch(ctx, url)
	if err != nil {
		_, _, err := u.Ask(ctx, tui.Static(FetchFailedPage(d.Page, w, url, err)))
		return err
	}
	if _, _, err := u.Ask(ctx, tui.Static(FetchedPage(d.Page, w, url, f))); err != nil {
		return err
	}
	for _, k := range f.Keys {
		// A key already in the window comes back as a duplicate; the others
		// are each confirmed next.
		_, _ = d.Window.OfferEnrolmentKey(ctx, connect.NewRequest(&accessv1.OfferEnrolmentKeyRequest{PublicKey: k.PublicKey, Via: access.ViaURL, From: url}))
	}
	return nil
}
