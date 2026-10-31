#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# mail.sh: LAB ONLY, the mail catcher the browser journeys set as the box's
# relay (docs/testing.md#the-browser-journeys): Mailpit in a container on
# the runner, with STARTTLS required on a certificate from a CA made for the
# run, so the box checks the relay's certificate as it would a real one.
#
#   mail.sh up     makes the CA and the relay's certificate (for RELAY_IP,
#                  where the box's mail goes), starts Mailpit with its SMTP
#                  on 127.0.0.1:1025 and its API on 127.0.0.1:8025, waits for
#                  it, and prints the driver's settings as NAME=value lines
#   mail.sh down   removes the container
#
# Inputs (environment):
#   WORK      a directory for the CA and the certificate (0700)
#   RELAY_IP  the address the box sends mail to (by default the journeys
#             driver's guest forward on QEMU's user network)
# The CA and the key are made for the run and thrown away with the runner.
set -euo pipefail
: "${WORK:?}"
relay_ip="${RELAY_IP:-10.0.2.100}" # scrub:allow=private-ip -- QEMU's user network
name=journeys-mail
image="axllent/mailpit:v1.31.6@sha256:23fe39e81bde596a918000b3135c0f85dc8bb4c9ea6be274b051143f3e300387"
say() { echo "journeys: mail: $*" >&2; }

up() {
  mkdir -p "$WORK"
  chmod 700 "$WORK"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -nodes \
    -keyout "$WORK/ca.key" -out "$WORK/ca.pem" -days 2 -subj "/CN=journeys mail CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -nodes \
    -keyout "$WORK/relay.key" -out "$WORK/relay.csr" -subj "/CN=$relay_ip" 2>/dev/null
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:%s\n' "$relay_ip" > "$WORK/relay.ext"
  openssl x509 -req -in "$WORK/relay.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" -CAcreateserial \
    -out "$WORK/relay.pem" -days 2 -extfile "$WORK/relay.ext" 2>/dev/null
  # Copied in rather than mounted, so it works wherever the docker daemon
  # runs; the container reads the pair as its own user.
  docker create --name "$name" -p 127.0.0.1:1025:1025 -p 127.0.0.1:8025:8025 \
    -e MP_SMTP_TLS_CERT=/tls/relay.pem -e MP_SMTP_TLS_KEY=/tls/relay.key \
    -e MP_SMTP_REQUIRE_STARTTLS=true "$image" >/dev/null
  mkdir -p "$WORK/tls"
  cp "$WORK/relay.pem" "$WORK/relay.key" "$WORK/tls/"
  chmod 644 "$WORK/tls/relay.pem" "$WORK/tls/relay.key"
  docker cp "$WORK/tls" "$name:/tls" >/dev/null
  docker start "$name" >/dev/null
  for _ in $(seq 60); do
    if curl -fsS http://127.0.0.1:8025/api/v1/info >/dev/null 2>&1; then
      say "Mailpit is up, STARTTLS required, its certificate for $relay_ip"
      echo "SNEAKERS_JOURNEYS_MAIL_SMTP=127.0.0.1:1025"
      echo "SNEAKERS_JOURNEYS_MAIL_API=http://127.0.0.1:8025"
      echo "SNEAKERS_JOURNEYS_MAIL_CA=$WORK/ca.pem"
      return 0
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  say "Mailpit didn't answer in 60s"
  return 1
}

down() { docker rm -f "$name" >/dev/null 2>&1 || true; }

case "${1:-}" in
  up) up ;;
  down) down ;;
  *) echo "usage: mail.sh up|down" >&2; exit 2 ;;
esac
