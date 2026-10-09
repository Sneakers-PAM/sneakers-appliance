// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package kubeapi is the appliance's small client for the installed k0s's
// API server, for the reads the appliance makes as its own service
// account. The admin kubeconfig is used for one thing only: a TokenRequest
// for that service account. Every read then goes with that short token
// and nothing else, so the account's Role, not the admin's rights, decides
// what can be read.
package kubeapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// tokenLife is how long a minted token lasts; it is reused until a minute
// before its end.
const tokenLife = 10 * time.Minute

// maxBody bounds what one answer may be.
const maxBody = 1 << 20

// callTimeout bounds one call to the API server.
const callTimeout = 10 * time.Second

// Client reads as Namespace/ServiceAccount, minting its tokens with the
// admin kubeconfig at Kubeconfig.
type Client struct {
	Kubeconfig                string
	Namespace, ServiceAccount string

	mu      sync.Mutex
	token   string
	expires time.Time
}

type kubeconfig struct {
	server   string
	pool     *x509.CertPool
	clientTL tls.Certificate
}

func (c *Client) config() (kubeconfig, error) {
	b, err := os.ReadFile(c.Kubeconfig)
	if err != nil {
		return kubeconfig{}, fmt.Errorf("kubeapi: the admin kubeconfig can't be read (is the product installed and k0s running?): %w", err)
	}
	var f struct {
		Clusters []struct {
			Cluster struct {
				Server string `yaml:"server"`
				CAData string `yaml:"certificate-authority-data"`
			} `yaml:"cluster"`
		} `yaml:"clusters"`
		Users []struct {
			User struct {
				CertData string `yaml:"client-certificate-data"`
				KeyData  string `yaml:"client-key-data"`
			} `yaml:"user"`
		} `yaml:"users"`
	}
	if err := yaml.Unmarshal(b, &f); err != nil || len(f.Clusters) == 0 || len(f.Users) == 0 {
		return kubeconfig{}, errors.New("kubeapi: the admin kubeconfig has no cluster or user")
	}
	dec := func(s string) []byte { d, _ := base64.StdEncoding.DecodeString(s); return d }
	k := kubeconfig{server: strings.TrimRight(f.Clusters[0].Cluster.Server, "/"), pool: x509.NewCertPool()}
	if !k.pool.AppendCertsFromPEM(dec(f.Clusters[0].Cluster.CAData)) {
		return kubeconfig{}, errors.New("kubeapi: the admin kubeconfig has no cluster CA")
	}
	k.clientTL, err = tls.X509KeyPair(dec(f.Users[0].User.CertData), dec(f.Users[0].User.KeyData))
	if err != nil {
		return kubeconfig{}, fmt.Errorf("kubeapi: the admin kubeconfig's client certificate: %w", err)
	}
	return k, nil
}

func client(k kubeconfig, withCert bool) *http.Client {
	cfg := &tls.Config{RootCAs: k.pool, MinVersion: tls.VersionTLS12}
	if withCert {
		cfg.Certificates = []tls.Certificate{k.clientTL}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: callTimeout}
}

// tokenFor returns a token for the service account, minting one with the
// admin's certificate when there's none or it nears its end.
func (c *Client) tokenFor(ctx context.Context, k kubeconfig) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Until(c.expires) > time.Minute {
		return c.token, nil
	}
	body, _ := json.Marshal(map[string]any{
		"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest",
		"spec": map[string]any{"expirationSeconds": int(tokenLife.Seconds())},
	})
	u := k.server + "/api/v1/namespaces/" + url.PathEscape(c.Namespace) + "/serviceaccounts/" + url.PathEscape(c.ServiceAccount) + "/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("kubeapi: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	out, err := do(client(k, true), req)
	if err != nil {
		return "", fmt.Errorf("kubeapi: a token for %s/%s: %w", c.Namespace, c.ServiceAccount, err)
	}
	var tr struct {
		Status struct {
			Token      string    `json:"token"`
			Expiration time.Time `json:"expirationTimestamp"`
		} `json:"status"`
	}
	if err := json.Unmarshal(out, &tr); err != nil || tr.Status.Token == "" {
		return "", errors.New("kubeapi: the token request's answer has no token")
	}
	c.token, c.expires = tr.Status.Token, tr.Status.Expiration
	return c.token, nil
}

func do(hc *http.Client, req *http.Request) ([]byte, error) {
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("%s %s: %s", req.Method, req.URL.Path, resp.Status)
	}
	return b, nil
}

// get reads path with the service account's token only.
func (c *Client) get(ctx context.Context, path string) ([]byte, error) {
	k, err := c.config()
	if err != nil {
		return nil, err
	}
	tok, err := c.tokenFor(ctx, k)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.server+path, nil)
	if err != nil {
		return nil, fmt.Errorf("kubeapi: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	b, err := do(client(k, false), req)
	if err != nil {
		return nil, fmt.Errorf("kubeapi: %w", err)
	}
	return b, nil
}

// SecretKey reads one key of one Secret. Nothing else of the Secret is
// returned.
func (c *Client) SecretKey(ctx context.Context, namespace, name, key string) (string, error) {
	b, err := c.get(ctx, "/api/v1/namespaces/"+url.PathEscape(namespace)+"/secrets/"+url.PathEscape(name))
	if err != nil {
		return "", err
	}
	var s struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return "", errors.New("kubeapi: the Secret doesn't parse")
	}
	enc, ok := s.Data[key]
	if !ok {
		return "", fmt.Errorf("kubeapi: the Secret %s/%s has no key %s", namespace, name, key)
	}
	v, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", fmt.Errorf("kubeapi: the Secret %s/%s's key %s doesn't decode", namespace, name, key)
	}
	return string(v), nil
}

// ServiceGet is a GET of path on a service through the API server's
// service proxy; proxy is <service>:<port>.
func (c *Client) ServiceGet(ctx context.Context, namespace, proxy, path string) ([]byte, error) {
	return c.get(ctx, "/api/v1/namespaces/"+url.PathEscape(namespace)+"/services/"+url.PathEscape(proxy)+"/proxy"+path)
}
