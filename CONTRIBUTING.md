# Contributing to sneakers-appliance

This repository follows the Sneakers-PAM workflow in the org
[CONTRIBUTING.md](https://github.com/Sneakers-PAM/.github/blob/main/.github/CONTRIBUTING.md):
issues from a template, a branch per issue, Conventional Commits, squash-merged PRs, and a
[DCO](DCO) sign-off (`git commit -s`) on every commit.

## Working on this repo

- Build and test: see [README.md](README.md). Run Go tests under a memory cap
  (`systemd-run --user --scope -q -p MemoryMax=6G -p MemorySwapMax=0 go test ./...`).
- Signing in tests and pull requests uses throwaway lab keys generated per run. Never commit a
  private key, and never use a production key outside the tag release job.
- Every `.go`, `.proto` and `.sh` file starts with the Apache-2.0 header:

  ```
  // Copyright 2026 The Sneakers-PAM Authors
  // SPDX-License-Identifier: Apache-2.0
  ```

  Files ported from another Apache-2.0 project keep their original copyright line next to this
  header, and `NOTICE` names the source. Code the original author (@Bugs5382) wrote for another
  of their projects is re-authored here as this project's own, with only this header.
- No real names, hosts, addresses or other identifiers in code, tests, fixtures or docs. Use
  example.org, 192.0.2.0/24, 2001:db8::/32 and invented names.
- CI: pushing to a PR branch cancels that PR's own still-running checks and starts fresh ones, so
  don't wait out a stale run. See [docs/testing.md](docs/testing.md) for what runs on a PR, what's
  path-filtered, and what reruns when the PR enters the merge queue.
