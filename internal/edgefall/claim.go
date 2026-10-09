// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package edgefall

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"
)

// ClaimOptions wire a Claimer.
type ClaimOptions struct {
	// HTTPS and HTTP are the addresses Traefik binds: :443 and :80.
	HTTPS, HTTP string
	// Cert is the box's certificate, read at every claim.
	Cert func() (tls.Certificate, error)
	// Handler serves 443.
	Handler http.Handler
	Logger  log.Logger
	// Listen binds; nil is net.Listen.
	Listen func(network, addr string) (net.Listener, error)
}

// Claimer holds 80 and 443 while it's wanted, both or neither, and lets
// them go when it isn't, so edgefall and Traefik never hold them together.
type Claimer struct {
	o ClaimOptions

	mu      sync.Mutex
	servers []*http.Server
	// failing logs a claim's first failure at warn, the retries at debug.
	failing bool
}

// NewClaimer returns a claimer that holds nothing yet.
func NewClaimer(o ClaimOptions) *Claimer {
	if o.Logger == nil {
		o.Logger = log.Nop()
	}
	if o.Listen == nil {
		o.Listen = net.Listen
	}
	return &Claimer{o: o}
}

// Want takes the ports when want and they're free, or lets them go. It's
// called on every poll, so a claim that fails (Traefik still has 443) is
// tried again on the next.
func (c *Claimer) Want(want bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch held := c.servers != nil; {
	case want && !held:
		if err := c.take(); err != nil {
			if !c.failing {
				c.o.Logger.Warn("edgefall: the edge isn't free yet; trying again", log.F("error", err.Error()))
			} else {
				c.o.Logger.Debug("edgefall: the edge isn't free yet", log.F("error", err.Error()))
			}
			c.failing = true
			return
		}
		c.failing = false
		c.o.Logger.Info("edgefall: holding the edge", log.F("https", c.o.HTTPS), log.F("http", c.o.HTTP))
	case !want && held:
		c.release()
		c.o.Logger.Info("edgefall: the edge is let go for Traefik")
	}
}

func (c *Claimer) take() error {
	cert, err := c.o.Cert()
	if err != nil {
		return err
	}
	ln443, err := c.o.Listen("tcp", c.o.HTTPS)
	if err != nil {
		return err
	}
	ln80, err := c.o.Listen("tcp", c.o.HTTP)
	if err != nil {
		_ = ln443.Close()
		return err
	}
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	https := HTTPServer(c.o.Handler)
	plain := HTTPServer(Redirect())
	c.servers = []*http.Server{https, plain}
	go c.serve(https, tls.NewListener(ln443, tlsConf))
	go c.serve(plain, ln80)
	return nil
}

func (c *Claimer) serve(s *http.Server, ln net.Listener) {
	if err := s.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		c.o.Logger.Error(err, "edgefall: serving the edge stopped")
	}
}

// HTTPServer is how edgefall serves h on every listener: short timeouts,
// small headers, and every request, OPTIONS * included, to h.
func HTTPServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, DisableGeneralOptionsHandler: true,
	}
}

// release closes the listeners and every open connection.
func (c *Claimer) release() {
	for _, s := range c.servers {
		_ = s.Close()
	}
	c.servers = nil
}

// Held is whether the ports are held.
func (c *Claimer) Held() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.servers != nil
}

// Close lets the ports go.
func (c *Claimer) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.release()
}

// WatchTaken dials addr (443, on loopback) every step after a handoff until
// something accepts, at most for limit, and reports how long it refused:
// the gap between edgefall letting 443 go and the edge binding it, or that
// nothing took it in time.
func WatchTaken(addr string, limit, step time.Duration, report func(gap time.Duration, taken bool)) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	target := net.JoinHostPort(host, port)
	start := time.Now()
	for time.Since(start) < limit {
		c, err := net.DialTimeout("tcp", target, step)
		if err == nil {
			_ = c.Close()
			report(time.Since(start), true)
			return
		}
		time.Sleep(step)
	}
	report(time.Since(start), false)
}
