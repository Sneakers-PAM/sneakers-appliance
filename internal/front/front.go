// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package front is sneakers-osadmin's side of :8443: it runs as the
// unprivileged osadmin user, serves the static pages with :8443's headers,
// and forwards the API (osadmin.v1, the upload and the audit export) to
// accessd on access.sock with the browser's address. It holds no session,
// key or store; accessd checks every call.
//
// While accessd is down every call answers that the appliance services are
// unavailable, except Status for a browser accessd accepted in the last
// session lifetime, which gets the last status seen (or the one accessd
// kept on disk) with an accessd health entry saying so.
package front

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/weblogin"
)

// apiPrefix is the :8443 API's path prefix.
const apiPrefix = "/sneakers.appliance.osadmin.v1."

// maxStatusBytes bounds a captured status response.
const maxStatusBytes = 1 << 20

// Options wire the front.
type Options struct {
	// Backend is accessd's base URL and Transport reaches it (a unix
	// socket dialer on the box).
	Backend   *url.URL
	Transport http.RoundTripper
	// Assets are the static pages; nil serves a short notice.
	Assets fs.FS
	// StatusFile is accessd's status cache, read when accessd is down and
	// this front has seen no status.
	StatusFile string
	Logger     log.Logger
}

// Front is sneakers-osadmin's handler.
type Front struct {
	o     Options
	proxy *httputil.ReverseProxy

	mu      sync.Mutex
	known   map[[32]byte]time.Time
	status  *osadminv1.GetStatusResponse
	statusT time.Time
}

// New returns the front.
func New(o Options) *Front {
	if o.Logger == nil {
		o.Logger = log.Nop()
	}
	f := &Front{o: o, known: map[[32]byte]time.Time{}}
	f.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(o.Backend)
			pr.Out.Header.Del(accessapi.ClientHeader)
			if host, _, err := net.SplitHostPort(pr.In.RemoteAddr); err == nil {
				pr.Out.Header.Set(accessapi.ClientHeader, host)
			}
			if isStatus(pr.In) {
				// Uncompressed, so the front can keep a copy.
				pr.Out.Header.Del("Accept-Encoding")
				pr.Out.Header.Del("Connect-Accept-Encoding")
			}
		},
		Transport:      o.Transport,
		ModifyResponse: f.observe,
		ErrorHandler:   f.down,
	}
	return f
}

// Handler serves :8443.
func (f *Front) Handler() http.Handler {
	pages := osadmin.StaticHandler(f.o.Assets)
	return osadmin.SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/"+osadminv1connect.LocalServiceName+"/"):
			http.NotFound(w, r)
		case strings.HasPrefix(r.URL.Path, apiPrefix), r.URL.Path == "/upload", r.URL.Path == "/export/audit-log":
			f.proxy.ServeHTTP(w, r)
		default:
			pages.ServeHTTP(w, r)
		}
	}))
}

func isStatus(r *http.Request) bool {
	return r.URL.Path == osadminv1connect.StatusServiceGetStatusProcedure
}

func cookieKey(r *http.Request) ([32]byte, bool) {
	c, err := r.Cookie(osadmin.CookieName)
	if err != nil || c.Value == "" {
		return [32]byte{}, false
	}
	return sha256.Sum256([]byte(c.Value)), true
}

// observe remembers the browsers accessd accepted and keeps the last
// status it answered.
func (f *Front) observe(res *http.Response) error {
	if res.StatusCode/100 != 2 {
		return nil
	}
	if k, ok := cookieKey(res.Request); ok {
		f.mu.Lock()
		f.known[k] = time.Now()
		f.mu.Unlock()
	}
	if !isStatus(res.Request) || res.Header.Get("Content-Encoding") != "" {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxStatusBytes+1))
	_ = res.Body.Close()
	if err != nil {
		return err
	}
	res.Body = io.NopCloser(bytes.NewReader(body))
	if len(body) > maxStatusBytes {
		return nil
	}
	st := &osadminv1.GetStatusResponse{}
	var uerr error
	if strings.HasPrefix(res.Header.Get("Content-Type"), "application/json") {
		uerr = protojson.Unmarshal(body, st)
	} else {
		uerr = proto.Unmarshal(body, st)
	}
	if uerr == nil {
		f.mu.Lock()
		f.status, f.statusT = st, time.Now()
		f.mu.Unlock()
	}
	return nil
}

// down answers a request accessd didn't take.
func (f *Front) down(w http.ResponseWriter, r *http.Request, err error) {
	f.o.Logger.Warn("osadmin: accessd isn't answering", log.F("path", r.URL.Path), log.F("error", err.Error()))
	if isStatus(r) && f.knownBrowser(r) {
		if st, ok := f.cachedStatus(); ok {
			f.writeStatus(w, r, st)
			return
		}
	}
	if strings.HasPrefix(r.URL.Path, apiPrefix) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": connect.CodeUnavailable.String(), "message": accessapi.Unavailable})
		return
	}
	http.Error(w, accessapi.Unavailable, http.StatusServiceUnavailable)
}

func (f *Front) knownBrowser(r *http.Request) bool {
	k, ok := cookieKey(r)
	if !ok {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	seen, ok := f.known[k]
	return ok && time.Since(seen) < weblogin.MaxAge
}

// cachedStatus is the newer of the last status seen and accessd's file,
// marked as coming from a cache with accessd down.
func (f *Front) cachedStatus() (*osadminv1.GetStatusResponse, bool) {
	f.mu.Lock()
	st, at := f.status, f.statusT
	f.mu.Unlock()
	if f.o.StatusFile != "" {
		if c, err := accessapi.ReadStatusCache(f.o.StatusFile); err == nil && (st == nil || c.Saved.After(at)) {
			st, at = c.Status, c.Saved
		}
	}
	if st == nil {
		return nil, false
	}
	out := proto.CloneOf(st)
	out.Health = append(out.Health, &osadminv1.Component{Name: "accessd", Ok: false, Detail: accessapi.Unavailable + " (status from " + at.UTC().Format(time.RFC3339) + ")"})
	return out, true
}

func (f *Front) writeStatus(w http.ResponseWriter, r *http.Request, st *osadminv1.GetStatusResponse) {
	var (
		b   []byte
		err error
	)
	ct := r.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "application/json"):
		b, err = protojson.Marshal(st)
	case strings.HasPrefix(ct, "application/proto"):
		b, err = proto.Marshal(st)
	default:
		err = errors.New("unsupported codec " + ct)
	}
	if err != nil {
		http.Error(w, accessapi.Unavailable, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", ct)
	_, _ = w.Write(b)
}
