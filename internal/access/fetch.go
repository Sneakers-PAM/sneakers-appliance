// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// The fetch's bounds: a published key list is a few lines.
const (
	fetchTimeout = 15 * time.Second
	fetchMax     = 64 * 1024
)

// Fetched is what FetchKeys found: the keys that pass the login key rules,
// each still to be confirmed, and why each other key line was refused.
type Fetched struct {
	Keys    []Key
	Refused []string
}

// FetchKeys reads an authorized_keys-format file over https (a code
// forge's published keys, say) with hc, whose CA bundle is the system's.
// Plain http, and any redirect to it, is refused (ACCESS_KEY_TYPE), as is
// a file with no acceptable key.
func FetchKeys(ctx context.Context, hc *http.Client, rawURL string) (Fetched, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return Fetched{}, codes.New(codes.AccessKeyType, "keys are fetched from an https:// URL only")
	}
	c := *hc
	c.Timeout = fetchTimeout
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return codes.New(codes.AccessKeyType, "the URL redirects to %s, which isn't https", req.URL.Redacted())
		}
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Fetched{}, err
	}
	resp, err := c.Do(req) // #nosec G107 G704 -- an https URL the admin typed on the console, to fetch their own public keys
	if err != nil {
		if code, ok := codes.Of(errors.Unwrap(err)); ok && code == codes.AccessKeyType {
			return Fetched{}, errors.Unwrap(err)
		}
		return Fetched{}, fmt.Errorf("fetch %s: %w", u.Redacted(), err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return Fetched{}, fmt.Errorf("fetch %s: %s", u.Redacted(), resp.Status)
	}
	var out Fetched
	sc := bufio.NewScanner(io.LimitReader(resp.Body, fetchMax))
	sc.Buffer(make([]byte, 4096), fetchMax)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, err := ParseLoginKey(line)
		if err != nil {
			out.Refused = append(out.Refused, codes.Describe(err))
			continue
		}
		out.Keys = append(out.Keys, k)
	}
	if len(out.Keys) == 0 {
		return out, codes.New(codes.AccessKeyType, "%s holds no acceptable public key", u.Redacted())
	}
	return out, nil
}
