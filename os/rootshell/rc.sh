#!/bin/sh
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# The root shell's start file. sneakers-elevated points ENV at it, so the
# interactive ash reads it before its first prompt: it defines help, the
# troubleshooting list for this box, and has kubectl, helm and k0s say
# plainly that they come with the product while none is installed.
# docs/ssh-and-elevation.md#the-root-shell has the session itself.

sneakers_product=/var/lib/sneakers/product/current

sneakers_need_product() {
  if [ ! -e "$sneakers_product/bundle.json" ]; then
    echo "No product is installed yet, so there's no $1: it comes with the product bundle (Updates on :8443)." >&2
    return 1
  fi
}

kubectl() { sneakers_need_product kubectl && command kubectl "$@"; }
helm() { sneakers_need_product helm && command helm "$@"; }
k0s() { sneakers_need_product k0s && "$sneakers_product/k0s" "$@"; }

help() {
  cat <<'HELP'
Troubleshooting this box (every key in this shell is recorded):

  kubectl get pods -A                 the product's pods and their state
  kubectl describe pod -n <ns> <pod>  why a pod isn't ready
  kubectl logs -n <ns> <pod>          a pod's log (-f follows, --previous after a restart)
  kubectl get events -A               recent cluster events
  k0s status                          k0s itself
  ls /var/lib/k0s/manifests           the stacks k0s applies
  ip addr; ip route                   the box's addresses and routes
  cat /etc/resolv.conf                the DNS servers the box uses
  nslookup <name>; nc -zv <host> <port>   name and port checks
  df -h /var/lib; free -m; top        disk, memory and processes
  dmesg | tail -n 50                  the kernel's latest messages
  ls /var/lib/sneakers/os-audit       the OS audit log

helm list -A is empty, and that's by design: the product's stacks are k0s
manifests the appliance applies from the installed bundle, not Helm
releases, because the box's update slots and revert track the manifests
directly and Helm's release state would sit outside them.

exit leaves the root shell; it also ends at its time limit or after 10
minutes without a key.
HELP
}
