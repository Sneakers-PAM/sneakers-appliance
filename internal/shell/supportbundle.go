// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// The bundle's colours, on a terminal only. A selection copied from a
// terminal carries the text, not these.
const (
	colorHeading = "\x1b[1;36m"
	colorError   = "\x1b[31m"
	colorWarn    = "\x1b[33m"
	colorReset   = "\x1b[0m"
)

var (
	errorLine = regexp.MustCompile(`(?i)\b(error|fatal|panic)\b|^# ended: .* result: (failed|timed out)|^[EF][0-9]{4} |\bfailed\b`)
	warnLine  = regexp.MustCompile(`(?i)\bwarn(ing)?\b|^W[0-9]{4} |\bresult: truncated`)
)

// maxRefusal bounds what's read of a refusal's text.
const maxRefusal = 4 << 10

// colourLine is line, with its newline, as a terminal shows it.
func colourLine(line string) string {
	body, nl := strings.CutSuffix(line, "\n")
	var c string
	switch {
	case strings.HasPrefix(body, "##### "), strings.HasPrefix(body, "==== "):
		c = colorHeading
	case errorLine.MatchString(body):
		c = colorError
	case warnLine.MatchString(body):
		c = colorWarn
	default:
		return line
	}
	body = c + body + colorReset
	if nl {
		body += "\n"
	}
	return body
}

// colourBundle colours the bundle's text as it passes, a line at a time.
func colourBundle(r io.Reader) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		br := bufio.NewReader(r)
		for {
			line, err := br.ReadString('\n')
			if line != "" {
				if _, werr := io.WriteString(pw, colourLine(line)); werr != nil {
					return
				}
			}
			if err != nil {
				_ = pw.CloseWithError(err)
				return
			}
		}
	}()
	return pr
}

// runSupportBundle asks for the short form, or with full every section,
// and colours it only when a person is reading it on a terminal.
func runSupportBundle(ctx context.Context, e *Env, _ *Command, args []string, flags map[string]string) (Result, error) {
	if len(args) == 1 && args[0] != "full" {
		return Result{}, codes.New(codes.ShellParse, "support-bundle takes full or nothing, not %q", Printable(args[0]))
	}
	res, err := e.Backend.Call(ctx, Request{Action: "support.bundle", Args: args})
	if err == nil && res.Stream != nil && e.Terminal && flags["no-color"] == "" {
		res.Stream = colourBundle(res.Stream)
	}
	return res, err
}

// UseBundleClient fetches the support bundle from accessd through hc,
// whose timeout gives the bundle the minutes it may take.
func (s *Services) UseBundleClient(hc *http.Client, baseURL string) {
	s.bundleClient, s.bundleURL = hc, strings.TrimSuffix(baseURL, "/")
}

// supportBundle starts the bundle: its text is the response's body. The
// identity is the peer uid, as for every call; the login's key and address
// are for the audit entry.
func (s *Services) supportBundle(ctx context.Context, args []string) (Result, error) {
	if s.bundleClient == nil {
		return Result{}, ErrUnavailable
	}
	url := s.bundleURL + accessapi.SupportBundlePath
	if len(args) == 1 {
		url += "?form=full"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Result{}, err
	}
	if s.Session.KeyFingerprint != "" {
		req.Header.Set(accessapi.KeyHeader, s.Session.KeyFingerprint)
	}
	if s.Session.Source != "" {
		req.Header.Set(accessapi.SourceHeader, s.Session.Source)
	}
	resp, err := s.bundleClient.Do(req)
	if err != nil {
		return Result{}, ErrUnavailable
	}
	if resp.StatusCode != http.StatusOK {
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxRefusal))
		msg := Printable(strings.TrimSpace(string(b)))
		if resp.StatusCode == http.StatusForbidden {
			return Result{}, codes.New(codes.AccessForbidden, "%s", msg)
		}
		return Result{}, codes.New(codes.NotAvailable, "%s", msg)
	}
	return Result{Stream: closingReader{resp.Body}}, nil
}

// closingReader closes the body at its end: an interactive session goes on
// after the bundle.
type closingReader struct{ rc io.ReadCloser }

func (c closingReader) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if err != nil {
		_ = c.rc.Close()
	}
	return n, err
}
