// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package journeys_test

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The driver's pieces that need no box, with their own tests, so they run
// with the unit tests on every pull request.

// boxProxy is the browser's way to the box: CONNECT to the box's 8443 or
// 443 only, each passed to QEMU's forward of that port. Anything else is
// refused.
type boxProxy struct {
	routes map[string]string
}

func (p boxProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	to, ok := p.routes[r.Host]
	if r.Method != http.MethodConnect || !ok {
		http.Error(w, "the journeys' proxy only connects to the box", http.StatusForbidden)
		return
	}
	up, err := net.DialTimeout("tcp", to, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = up.Close()
		http.Error(w, "no hijacking", http.StatusInternalServerError)
		return
	}
	down, buf, err := hj.Hijack()
	if err != nil {
		_ = up.Close()
		return
	}
	_, _ = down.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	go func() {
		defer func() { _ = up.Close() }()
		_, _ = io.Copy(up, buf)
	}()
	go func() {
		defer func() { _ = down.Close() }()
		_, _ = io.Copy(down, up)
	}()
}

// serve runs h on a port of the runner's loopback until the test ends, and
// answers its address.
func serve(t *testing.T, h http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

var ppmHeader = regexp.MustCompile(`^P6\s+(\d+)\s+(\d+)\s+(\d+)\s`)

// decodePPM reads QEMU's binary screendump (P6, 8 bits a sample).
func decodePPM(b []byte) (image.Image, error) {
	m := ppmHeader.FindSubmatch(b)
	if m == nil {
		return nil, errors.New("the screendump isn't a binary PPM")
	}
	w, _ := strconv.Atoi(string(m[1]))
	h, _ := strconv.Atoi(string(m[2]))
	px := b[len(m[0]):]
	if string(m[3]) != "255" || len(px) < w*h*3 {
		return nil, fmt.Errorf("the screendump is %dx%d with max %s and %d bytes of pixels", w, h, m[3], len(px))
	}
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			i := (y*w + x) * 3
			img.Set(x, y, color.RGBA{R: px[i], G: px[i+1], B: px[i+2], A: 255})
		}
	}
	return img, nil
}

func TestTheProxyConnectsOnlyToTheBox(t *testing.T) {
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = up.Close() }()
	go func() {
		for {
			c, err := up.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				line, _ := bufio.NewReader(c).ReadString('\n')
				_, _ = c.Write([]byte("echo " + line))
			}()
		}
	}()
	proxy := serve(t, boxProxy{routes: map[string]string{"192.0.2.15:8443": up.Addr().String()}})

	connect := func(target string) (net.Conn, string) {
		c, err := net.DialTimeout("tcp", proxy, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		status, _ := bufio.NewReader(c).ReadString('\n')
		return c, strings.TrimSpace(status)
	}

	c, status := connect("192.0.2.15:8443")
	if status != "HTTP/1.1 200 Connection established" {
		t.Fatalf("CONNECT to the box's 8443: %q", status)
	}
	// The proxy writes only its status line, so what follows is the
	// forward's own answer.
	_, _ = c.Write([]byte("hello\n"))
	got, _ := bufio.NewReader(c).ReadString('\n')
	_ = c.Close()
	if got != "echo hello\n" {
		t.Fatalf("through the tunnel: %q", got)
	}
	for _, target := range []string{"192.0.2.15:22", "192.0.2.16:8443", "127.0.0.1:" + strings.Split(up.Addr().String(), ":")[1]} {
		c, status := connect(target)
		_ = c.Close()
		if !strings.Contains(status, "403") {
			t.Errorf("CONNECT %s: %q, want it refused", target, status)
		}
	}
	resp, err := http.Get("http://" + proxy + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("a plain GET through the proxy: %s, want it refused", resp.Status)
	}
}

func TestTheScreendumpReadsAsAnImage(t *testing.T) {
	ppm := append([]byte("P6\n2 1\n255\n"), 255, 0, 0, 0, 0, 255)
	img, err := decodePPM(ppm)
	if err != nil {
		t.Fatal(err)
	}
	if b := img.Bounds(); b.Dx() != 2 || b.Dy() != 1 {
		t.Fatalf("bounds %v", b)
	}
	if got := color.RGBAModel.Convert(img.At(0, 0)); got != (color.RGBA{R: 255, A: 255}) {
		t.Errorf("pixel 0: %v", got)
	}
	if got := color.RGBAModel.Convert(img.At(1, 0)); got != (color.RGBA{B: 255, A: 255}) {
		t.Errorf("pixel 1: %v", got)
	}
	for _, bad := range [][]byte{[]byte("P3\n2 1\n255\n0 0 0"), []byte("P6\n2 1\n255\n\x00\x00"), bytes.Repeat([]byte{0}, 4)} {
		if _, err := decodePPM(bad); err == nil {
			t.Errorf("decodePPM(%q) took it", bad)
		}
	}
}
