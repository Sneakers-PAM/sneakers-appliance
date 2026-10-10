// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package boxsettings

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// sendTimeout bounds a test email: the dial and the whole conversation.
const sendTimeout = 30 * time.Second

func sendFailed(step string, err error) error {
	return codes.New(codes.EmailSend, "%s: %v", step, err)
}

// Send sends a short test email to to through e, the same way the
// product's mail goes: the TLS mode, the certificate check with the
// relay's CA, and AUTH (PLAIN, else LOGIN) when a username is set. It
// returns the relay's answer to the message. No error carries the
// password.
func Send(ctx context.Context, e Email, to string) (string, error) {
	if !e.Configured() {
		return "", codes.New(codes.EmailInvalid, "no relay is set")
	}
	if err := e.Check(); err != nil {
		return "", err
	}
	if a, err := mail.ParseAddress(to); err != nil || a.Name != "" || a.Address != to {
		return "", codes.New(codes.EmailInvalid, "the test address %q isn't a plain email address", to)
	}
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	c, err := dial(ctx, e)
	if err != nil {
		return "", err
	}
	defer func() { _ = c.Close() }()
	if err := secure(c, e); err != nil {
		return "", err
	}
	if err := c.Mail(e.From); err != nil {
		return "", sendFailed("the relay refused the from address", err)
	}
	if err := c.Rcpt(to); err != nil {
		return "", sendFailed("the relay refused the test address", err)
	}
	w, err := c.Data()
	if err != nil {
		return "", sendFailed("the relay refused the message", err)
	}
	if _, err := w.Write(message(e.From, to)); err != nil {
		_ = w.Close()
		return "", sendFailed("the message didn't go out", err)
	}
	if err := w.Close(); err != nil {
		return "", sendFailed("the relay didn't take the message", err)
	}
	_ = c.Quit()
	return "the relay took the message", nil
}

func dial(ctx context.Context, e Email) (*smtp.Client, error) {
	addr := net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
	tlsCfg, err := tlsConfig(e)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, sendFailed("the relay "+addr+" can't be reached", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if e.TLS == TLSImplicit {
		tc := tls.Client(conn, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, sendFailed("TLS with the relay failed", err)
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, e.Host)
	if err != nil {
		_ = conn.Close()
		return nil, sendFailed("the relay didn't greet", err)
	}
	return c, nil
}

func tlsConfig(e Email) (*tls.Config, error) {
	// #nosec G402 -- verification off is the admin's choice on the Email
	// page, which warns about it.
	cfg := &tls.Config{ServerName: e.Host, InsecureSkipVerify: !e.Verify, MinVersion: tls.VersionTLS12} //nolint:gosec
	if e.CA != "" {
		pool, err := e.pool()
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

func secure(c *smtp.Client, e Email) error {
	if e.TLS == TLSStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return codes.New(codes.EmailSend, "the relay doesn't offer STARTTLS; nothing was sent")
		}
		cfg, err := tlsConfig(e)
		if err != nil {
			return err
		}
		if err := c.StartTLS(cfg); err != nil {
			return sendFailed("STARTTLS with the relay failed", err)
		}
	}
	if e.Username == "" {
		return nil
	}
	ok, mechs := c.Extension("AUTH")
	if !ok {
		return codes.New(codes.EmailSend, "the relay offers no AUTH, and a username is set")
	}
	a := &relayAuth{user: e.Username, pass: e.Password, login: !slices.Contains(strings.Fields(strings.ToUpper(mechs)), "PLAIN")}
	if err := c.Auth(a); err != nil {
		return sendFailed("the relay refused the username and password", scrub(err, e.Password))
	}
	return nil
}

// scrub keeps the password out of an error a relay echoed it in.
func scrub(err error, pass string) error {
	if pass == "" || !strings.Contains(err.Error(), pass) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), pass, "[password]"))
}

// relayAuth is AUTH PLAIN, or LOGIN for a relay that offers only that.
// Unlike smtp.PlainAuth it also authenticates over a connection that isn't
// encrypted: with TLS off the admin chose that, and the page warns.
type relayAuth struct {
	user, pass string
	login      bool
	step       int
}

func (a *relayAuth) Start(*smtp.ServerInfo) (string, []byte, error) {
	if a.login {
		return "LOGIN", nil, nil
	}
	return "PLAIN", []byte("\x00" + a.user + "\x00" + a.pass), nil
}

func (a *relayAuth) Next(_ []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	if !a.login {
		return nil, errors.New("unexpected relay challenge")
	}
	a.step++
	switch a.step {
	case 1:
		return []byte(a.user), nil
	case 2:
		return []byte(a.pass), nil
	}
	return nil, errors.New("unexpected relay challenge")
}

func message(from, to string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: Test email from the appliance\r\nDate: %s\r\n", from, to, time.Now().UTC().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=\"utf-8\"\r\n\r\n")
	b.WriteString("This is a test email from the appliance's Email page. The product sends its mail\r\nthrough this relay with the same settings.\r\n")
	return []byte(b.String())
}
