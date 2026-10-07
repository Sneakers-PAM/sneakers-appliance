// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package enrol

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
)

// Accessd is the part of access.v1's EnrolmentService sneakers-enrol uses.
type Accessd interface {
	SubmitEnrolmentCode(context.Context, *connect.Request[accessv1.SubmitEnrolmentCodeRequest]) (*connect.Response[accessv1.SubmitEnrolmentCodeResponse], error)
	GetEnrolmentKey(context.Context, *connect.Request[accessv1.GetEnrolmentKeyRequest]) (*connect.Response[accessv1.GetEnrolmentKeyResponse], error)
}

// ErrNotEnrolled is a session that ended without its key stored.
var ErrNotEnrolled = errors.New("the key wasn't enrolled")

// RunSession is sneakers-enrol, the enrol account's forced command: it
// asks for the code shown on the console, sends it with the key sshd
// authenticated, and waits until the console accepts or refuses the key.
// It reads only the code from in; nothing else the client sends does
// anything.
func RunSession(ctx context.Context, in io.Reader, out io.Writer, c Accessd, login accessapi.Login, poll time.Duration) error {
	if _, isCert := login.Key.(*ssh.Certificate); isCert || login.Key == nil {
		_, _ = fmt.Fprintln(out, "Connect with the plain key you want to enrol, not a certificate.")
		return ErrNotEnrolled
	}
	fp := ssh.FingerprintSHA256(login.Key)
	_, _ = fmt.Fprintf(out, "Enrolling key %s (%s) from %s.\r\n", fp, login.Key.Type(), login.Source)
	lines := bufio.NewScanner(io.LimitReader(in, 4096))
	var sub *connect.Response[accessv1.SubmitEnrolmentCodeResponse]
	for {
		_, _ = fmt.Fprint(out, "Enrolment code shown on the console: ")
		if !lines.Scan() {
			_, _ = fmt.Fprintln(out)
			return ErrNotEnrolled
		}
		var err error
		sub, err = c.SubmitEnrolmentCode(ctx, connect.NewRequest(&accessv1.SubmitEnrolmentCodeRequest{Code: strings.TrimSpace(lines.Text()), PublicKey: login.KeyLine}))
		if err == nil {
			break
		}
		_, _ = fmt.Fprintf(out, "%s\r\n", message(err))
		if !strings.Contains(err.Error(), "ENROL_CODE") || strings.Contains(err.Error(), "window closed") {
			return ErrNotEnrolled
		}
	}
	admin := sub.Msg.GetAdmin()
	_, _ = fmt.Fprintf(out, "Waiting for the console: it shows key %s for admin %s. Type yes there to store it.\r\n", fp, admin)
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ErrNotEnrolled
		case <-t.C:
		}
		k, err := c.GetEnrolmentKey(ctx, connect.NewRequest(&accessv1.GetEnrolmentKeyRequest{Id: sub.Msg.GetId()}))
		if err != nil {
			_, _ = fmt.Fprintf(out, "%s\r\n", message(err))
			return ErrNotEnrolled
		}
		switch KeyState(k.Msg.GetKey().GetState()) {
		case Accepted:
			_, _ = fmt.Fprintf(out, "Key enrolled for %s. To enrol another key of %s while the window is open, connect again with that key: ssh enrol@<address>\r\n", admin, admin)
			return nil
		case Rejected:
			_, _ = fmt.Fprintln(out, "The console refused the key.")
			return ErrNotEnrolled
		}
	}
}

func message(err error) string {
	var ce *connect.Error
	if errors.As(err, &ce) {
		if ce.Code() == connect.CodeUnavailable {
			return accessapi.Unavailable
		}
		return ce.Message()
	}
	return accessapi.Unavailable
}
