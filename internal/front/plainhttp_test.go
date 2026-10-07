// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package front_test

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/front"
)

// tlsOnly serves :8443's way: TLS on a listener that answers plain HTTP
// with a redirect.
func tlsOnly(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "secure content")
	}))
	ts.Listener = front.TLSOnly(ts.Listener, nil)
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts, &hits
}

// plain sends raw over plain TCP and returns the response.
func plain(t *testing.T, ts *httptest.Server, raw string) (*http.Response, string) {
	t.Helper()
	c, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatal(err)
	}
	res, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	return res, string(body)
}

func port(ts *httptest.Server) string {
	_, p, _ := net.SplitHostPort(ts.Listener.Addr().String())
	return p
}

func TestPlainHTTPIsRedirectedToHTTPS(t *testing.T) {
	ts, hits := tlsOnly(t)
	res, body := plain(t, ts, "GET /status?tab=disk HTTP/1.1\r\nHost: box1.sneakers.example.org:8443\r\n\r\n")
	want := "https://box1.sneakers.example.org:" + port(ts) + "/status?tab=disk"
	if res.StatusCode != http.StatusMovedPermanently || res.Header.Get("Location") != want {
		t.Fatalf("%d %q", res.StatusCode, res.Header.Get("Location"))
	}
	if !strings.Contains(body, "Redirecting you to https") || !strings.Contains(body, `href="`+want+`"`) {
		t.Fatalf("body %q", body)
	}
	if strings.Contains(body, "secure content") || hits.Load() != 0 {
		t.Fatal("plain HTTP reached the handler")
	}
}

func TestPlainHTTPToAnAddressKeepsTheAddress(t *testing.T) {
	ts, _ := tlsOnly(t)
	res, _ := plain(t, ts, "POST /sneakers.appliance.osadmin.v1.PowerService/Reboot HTTP/1.1\r\nHost: [2001:db8::10]:8443\r\nContent-Length: 2\r\n\r\n{}")
	want := "https://[2001:db8::10]:" + port(ts) + "/sneakers.appliance.osadmin.v1.PowerService/Reboot"
	if res.StatusCode != http.StatusMovedPermanently || res.Header.Get("Location") != want {
		t.Fatalf("%d %q", res.StatusCode, res.Header.Get("Location"))
	}
}

func TestPlainHTTPWithABadHostGoesToTheListenerAddress(t *testing.T) {
	ts, _ := tlsOnly(t)
	for _, host := range []string{"", "evil.example.org/\"><script>", "a b"} {
		raw := "GET / HTTP/1.1\r\n"
		if host != "" {
			raw += "Host: " + host + "\r\n"
		}
		res, body := plain(t, ts, raw+"\r\n")
		want := "https://" + ts.Listener.Addr().String() + "/"
		if res.StatusCode != http.StatusMovedPermanently || res.Header.Get("Location") != want {
			t.Errorf("host %q: %d %q", host, res.StatusCode, res.Header.Get("Location"))
		}
		if strings.Contains(body, "<script>") {
			t.Errorf("host %q reached the body: %q", host, body)
		}
	}
}

func TestTLSIsServedAsBefore(t *testing.T) {
	ts, hits := tlsOnly(t)
	// A client that connects and says nothing doesn't hold up the others.
	idle, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = idle.Close() }()
	res, err := ts.Client().Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if string(body) != "secure content" || hits.Load() != 1 || res.TLS == nil {
		t.Fatalf("%q %d", body, hits.Load())
	}
}

func TestClosingTheListenerStopsTheServer(t *testing.T) {
	ts, _ := tlsOnly(t)
	ts.Close()
	if _, err := net.DialTimeout("tcp", ts.Listener.Addr().String(), time.Second); err == nil {
		t.Fatal("still accepting")
	}
}
