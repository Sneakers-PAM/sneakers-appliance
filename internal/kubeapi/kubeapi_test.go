// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package kubeapi_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/kubeapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
)

type apiServer struct {
	mu       sync.Mutex
	tokens   int
	requests []string
}

func newAPI(t *testing.T) (*apiServer, string) {
	t.Helper()
	ca := testpki.NewTLSCA(t)
	srvLeaf := ca.Issue(t, testpki.LeafOptions{Names: []string{"127.0.0.1"}})
	admin := ca.Issue(t, testpki.LeafOptions{Names: []string{"kubernetes-admin"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	a := &apiServer{}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		hasCert := r.TLS != nil && len(r.TLS.PeerCertificates) > 0
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		a.requests = append(a.requests, fmt.Sprintf("%s %s cert=%v bearer=%s", r.Method, r.URL.Path, hasCert, bearer))
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/namespaces/sneakers-appliance/serviceaccounts/exposed-values/token":
			if !hasCert || bearer != "" {
				http.Error(w, "the admin mints the token", http.StatusUnauthorized)
				return
			}
			a.tokens++
			_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{
				"token": fmt.Sprintf("tok-%d", a.tokens), "expirationTimestamp": time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339),
			}})
		case hasCert || !strings.HasPrefix(bearer, "tok-"):
			http.Error(w, "only the service account reads", http.StatusForbidden)
		case r.URL.Path == "/api/v1/namespaces/sneakers/secrets/sneakers-setup-token":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{
				"SETUP_TOKEN": base64.StdEncoding.EncodeToString([]byte("stp_value")),
				"OTHER":       base64.StdEncoding.EncodeToString([]byte("not this one")),
			}})
		case r.URL.Path == "/api/v1/namespaces/sneakers/services/sneakers-gateway:http/proxy/setup/state":
			_, _ = w.Write([]byte(`{"needsSetup": false}`))
		default:
			http.NotFound(w, r)
		}
	}))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{srvLeaf.Cert.Raw, ca.Intermediate.Raw}, PrivateKey: srvLeaf.Key}}, ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	b64 := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
	cfg := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- cluster:
    server: %s
    certificate-authority-data: %s
  name: local
contexts:
- context: {cluster: local, user: admin}
  name: admin
current-context: admin
users:
- name: admin
  user:
    client-certificate-data: %s
    client-key-data: %s
`, ts.URL, b64(append(append([]byte{}, ca.RootPEM...), ca.IntermediatePEM...)), b64(admin.PEM), b64(admin.KeyPEM))
	p := filepath.Join(t.TempDir(), "admin.conf")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return a, p
}

// The admin kubeconfig only mints a short token for the appliance's own
// service account; every read goes with that token alone, so what the
// box can read is what that account's Role allows.
func TestReadsGoThroughTheServiceAccount(t *testing.T) {
	a, conf := newAPI(t)
	c := &kubeapi.Client{Kubeconfig: conf, Namespace: "sneakers-appliance", ServiceAccount: "exposed-values"}
	ctx := context.Background()
	v, err := c.SecretKey(ctx, "sneakers", "sneakers-setup-token", "SETUP_TOKEN")
	if err != nil || v != "stp_value" {
		t.Fatalf("%q %v", v, err)
	}
	body, err := c.ServiceGet(ctx, "sneakers", "sneakers-gateway:http", "/setup/state")
	if err != nil || !strings.Contains(string(body), "needsSetup") {
		t.Fatalf("%s %v", body, err)
	}
	if _, err := c.SecretKey(ctx, "sneakers", "sneakers-setup-token", "MISSING"); err == nil {
		t.Fatal("a missing key read")
	}
	if _, err := c.SecretKey(ctx, "sneakers", "other", "SETUP_TOKEN"); err == nil {
		t.Fatal("an unknown Secret read")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tokens != 1 {
		t.Fatalf("%d tokens minted; one is reused until it nears its end", a.tokens)
	}
	for _, r := range a.requests[1:] {
		if strings.Contains(r, "cert=true") || !strings.Contains(r, "bearer=tok-1") {
			t.Fatalf("a read went with the admin's certificate or no token: %s", r)
		}
	}
}

func TestNoKubeconfigIsAnError(t *testing.T) {
	c := &kubeapi.Client{Kubeconfig: filepath.Join(t.TempDir(), "none"), Namespace: "n", ServiceAccount: "s"}
	if _, err := c.SecretKey(context.Background(), "a", "b", "c"); err == nil {
		t.Fatal("read without a kubeconfig")
	}
}
