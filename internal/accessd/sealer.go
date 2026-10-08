// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd

import (
	"context"
	"time"

	"connectrpc.com/connect"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
)

// sealTimeout bounds one call to init: a sealed item is small.
const sealTimeout = 30 * time.Second

// CustodySealer seals accessd's secrets (the root key, the pepper and the
// setup code) through init's KeyCustody on init.sock.
type CustodySealer struct {
	Client initv1connect.KeyCustodyServiceClient
}

// Seal stores secret as the sealed item name.
func (s CustodySealer) Seal(name string, secret []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), sealTimeout)
	defer cancel()
	_, err := s.Client.Seal(ctx, connect.NewRequest(&initv1.SealRequest{Name: name, Secret: secret}))
	return err
}

// Unseal returns the sealed item name; ok is false when it was never
// sealed.
func (s CustodySealer) Unseal(name string) ([]byte, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sealTimeout)
	defer cancel()
	r, err := s.Client.Unseal(ctx, connect.NewRequest(&initv1.UnsealRequest{Name: name}))
	if connect.CodeOf(err) == connect.CodeNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return r.Msg.GetSecret(), true, nil
}
