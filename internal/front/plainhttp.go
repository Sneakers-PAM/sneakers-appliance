// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package front

import (
	"bufio"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"
)

// tlsHandshake is the first byte of every TLS connection: a handshake
// record.
const tlsHandshake = 0x16

// sniffTimeout bounds how long a new connection may take to send its first
// byte, and a plain HTTP client its request line and headers.
const sniffTimeout = 10 * time.Second

// maxPlainRequest bounds what is read of a plain HTTP request.
const maxPlainRequest = 16 << 10

var hostname = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// TLSOnly wraps the :8443 listener: a connection that opens with a TLS
// handshake is passed on untouched, and one that opens with anything else
// (a browser asking for http://) gets a redirect to the same host, port
// and path over https and is closed. Nothing else is served over plain
// HTTP. Each connection's first byte is read off the accept path, so a
// client that connects and says nothing holds up no one.
func TLSOnly(ln net.Listener, lg log.Logger) net.Listener {
	if lg == nil {
		lg = log.Nop()
	}
	t := &tlsOnly{Listener: ln, lg: lg, conns: make(chan net.Conn), errs: make(chan error), done: make(chan struct{})}
	go t.loop()
	return t
}

type tlsOnly struct {
	net.Listener
	lg    log.Logger
	conns chan net.Conn
	errs  chan error
	done  chan struct{}
	once  sync.Once
}

func (t *tlsOnly) loop() {
	for {
		c, err := t.Listener.Accept()
		if err != nil {
			select {
			case t.errs <- err:
			case <-t.done:
				return
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go t.sniff(c)
	}
}

func (t *tlsOnly) Accept() (net.Conn, error) {
	select {
	case c := <-t.conns:
		return c, nil
	case err := <-t.errs:
		return nil, err
	case <-t.done:
		return nil, net.ErrClosed
	}
}

func (t *tlsOnly) Close() error {
	t.once.Do(func() { close(t.done) })
	return t.Listener.Close()
}

func (t *tlsOnly) sniff(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(sniffTimeout))
	br := bufio.NewReader(c)
	first, err := br.Peek(1)
	if err != nil {
		_ = c.Close()
		return
	}
	if first[0] != tlsHandshake {
		t.redirect(c, br)
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	select {
	case t.conns <- &peeked{Conn: c, r: br}:
	case <-t.done:
		_ = c.Close()
	}
}

// redirect answers a plain HTTP request with a 301 to its https URL.
func (t *tlsOnly) redirect(c net.Conn, br *bufio.Reader) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(sniffTimeout))
	target := t.target(c, br)
	body := fmt.Sprintf("<!DOCTYPE html>\n<title>Redirecting to https</title>\n<p>Redirecting you to https&hellip; <a href=\"%s\">%s</a></p>\n", html.EscapeString(target), html.EscapeString(target))
	_, err := fmt.Fprintf(c, "HTTP/1.1 301 Moved Permanently\r\nLocation: %s\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n%s", target, len(body), body)
	if err != nil {
		t.lg.Warn("osadmin: the https redirect wasn't sent", log.F("client", c.RemoteAddr().String()), log.F("error", err.Error()))
		return
	}
	t.lg.Info("osadmin: plain HTTP redirected to https", log.F("client", c.RemoteAddr().String()), log.F("to", target))
}

// target is https://<host>:<this port><path>, the host taken from the
// request when it is a plain host name or address, else this listener's
// address.
func (t *tlsOnly) target(c net.Conn, br *bufio.Reader) string {
	local, port, _ := net.SplitHostPort(c.LocalAddr().String())
	host, uri := local, "/"
	req, err := http.ReadRequest(bufio.NewReader(io.LimitReader(br, maxPlainRequest)))
	if err == nil {
		if h := requestHost(req.Host); h != "" {
			host = h
		}
		if u := req.URL.RequestURI(); strings.HasPrefix(u, "/") && !strings.HasPrefix(u, "//") {
			uri = u
		}
	}
	return "https://" + net.JoinHostPort(host, port) + uri
}

func requestHost(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.String()
	}
	if hostname.MatchString(h) {
		return h
	}
	return ""
}

// peeked is a connection whose first bytes were read into r.
type peeked struct {
	net.Conn
	r *bufio.Reader
}

func (p *peeked) Read(b []byte) (int, error) { return p.r.Read(b) }
