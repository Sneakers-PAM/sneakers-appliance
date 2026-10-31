#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# A pull request whose every changed path is documentation (*.md, docs/**)
# runs only the scrub, PR Checks and the label checker. Every other job skips,
# and a job skipped by its `if:` reports success under its own name, so the
# required checks still pass and nothing hangs. Any other path, or any event
# that isn't a pull request (push to main, the nightly run, workflow_dispatch,
# workflow_call), runs everything. YamlLint and Actionlint also skip on a code
# PR that changes no YAML or no workflow.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
wf="$root/.github/workflows"
classify="$here/changes.sh"
fail=0
bad() { echo "FAIL: $*" >&2; fail=1; }

# expect <event> <want> <paths...>: the classifier's output for those paths.
expect() {
  local event="$1" want="$2" got
  shift 2
  got="$(printf '%s\n' "$@" | bash "$classify" "$event" | tr '\n' ' ')"
  [ "$got" = "$want" ] || bad "$event [$*]: got '$got', want '$want'"
}

expect pull_request "docs_only=true yaml=false workflows=false journeys=false " AGENTS.md
expect pull_request "docs_only=true yaml=false workflows=false journeys=false " CLAUDE.md docs/testing.md docs/runbooks/a.md README.md os/README.md
expect pull_request "docs_only=true yaml=false workflows=false journeys=false " docs/diagram.svg
expect pull_request "docs_only=false yaml=false workflows=false journeys=true " docs/testing.md internal/netd/netd.go
expect pull_request "docs_only=false yaml=false workflows=false journeys=true " internal/netd/netd.go
expect pull_request "docs_only=false yaml=false workflows=false journeys=false " README.md.orig
expect pull_request "docs_only=false yaml=true workflows=false journeys=false " deploy/stack.yaml
expect pull_request "docs_only=false yaml=true workflows=false journeys=false " .yamllint
expect pull_request "docs_only=false yaml=true workflows=true journeys=false " .github/workflows/checks.yml
expect pull_request "docs_only=false yaml=false workflows=true journeys=false " .github/actions/x/run.sh
# The browser journeys run on what goes into the image or its build, and on
# the journeys themselves; not on docs, the other workflows or other tests.
expect pull_request "docs_only=false yaml=false workflows=false journeys=true " test/e2e/journeys/specs/01-first-run-setup.spec.ts
expect pull_request "docs_only=false yaml=false workflows=false journeys=true " test/image/journeys/journeys_test.go
expect pull_request "docs_only=false yaml=false workflows=false journeys=true " test/image/harness/screen.go
expect pull_request "docs_only=false yaml=false workflows=false journeys=true " build/release/pins.env
expect pull_request "docs_only=false yaml=false workflows=false journeys=true " os/kernel/amd64.config go.sum
expect pull_request "docs_only=false yaml=true workflows=true journeys=true " .github/workflows/image-e2e.yml
expect pull_request "docs_only=false yaml=false workflows=false journeys=false " test/image/k0s/k0s_test.go test/kit/refusal_test.go scripts/x.sh
expect pull_request "docs_only=true yaml=false workflows=false journeys=false " test/e2e/journeys/README.md
# No list (a failed diff) runs everything.
expect pull_request "docs_only=false yaml=true workflows=true journeys=true "
for event in push schedule workflow_dispatch workflow_call; do
  expect "$event" "docs_only=false yaml=true workflows=true journeys=true " AGENTS.md
done

# The wiring: which jobs gate on the classifier, and how. The required check
# names come from docs/repo-settings.md, which mirrors the ruleset.
python3 - "$wf" "$root/docs/repo-settings.md" <<'PY' || fail=1
import os, re, sys, yaml

wf, settings = sys.argv[1], sys.argv[2]
fail = False
def bad(msg):
    global fail
    print("FAIL: " + msg, file=sys.stderr)
    fail = True

jobs = {}  # job name -> (file, job id, job)
docs = {}
for f in sorted(os.listdir(wf)):
    if not f.endswith((".yml", ".yaml")):
        continue
    with open(os.path.join(wf, f)) as fh:
        doc = yaml.safe_load(fh)
    docs[f] = doc
    for jid, job in (doc.get("jobs") or {}).items():
        jobs[job.get("name", jid)] = (f, jid, job)

text = open(settings).read()
m = re.search(r"requires these checks: (.*?)\.\n\n", text, re.S)
required = re.findall(r"`([^`]+)`", m.group(1)) if m else []
if len(required) < 6:
    bad("docs/repo-settings.md doesn't list the required checks")
for name in required:
    if name == "checks / scrub":
        if "checks" not in (docs["checks.yml"].get("jobs") or {}):
            bad("checks.yml lost its `checks` job (the `checks / scrub` check)")
        continue
    if name not in jobs:
        bad(f"no job is named the required check '{name}'")

def gate(f, jid, job, output):
    cond = str(job.get("if", ""))
    needs = job.get("needs", [])
    needs = [needs] if isinstance(needs, str) else needs
    if "changes" not in needs:
        bad(f"{f} {jid} doesn't need the changes job")
    calls = (docs[f]["jobs"].get("changes") or {}).get("uses", "")
    if calls != "./.github/workflows/changes.yml":
        bad(f"{f}: the changes job doesn't call ./.github/workflows/changes.yml")
    # !cancelled() keeps the job from being skipped (and passing) when the
    # classifier itself fails: a failed classifier runs everything.
    if "!cancelled()" not in cond:
        bad(f"{f} {jid}: its if doesn't start from !cancelled(), so a failed classifier would skip it")
    if output == "docs_only":
        if "needs.changes.outputs.docs_only != 'true'" not in cond:
            bad(f"{f} {jid}: its if doesn't skip on a docs-only change")
    else:
        if f"needs.changes.outputs.{output} == 'true'" not in cond or "needs.changes.result != 'success'" not in cond:
            bad(f"{f} {jid}: its if doesn't run on {output} changes (or on a failed classifier)")

heavy = {
    "image-e2e.yml": ["image"],
    "job-go-lang-ci.yaml": ["build-test", "lint", "lab-tools"],
    "job-go-security.yaml": ["govulncheck", "gosec"],
    "job-golic.yaml": ["golic"],
    "job-license-check-go.yaml": ["go"],
    "job-static-tools.yaml": ["static-tools"],
}
for f, ids in heavy.items():
    for jid in ids:
        gate(f, jid, docs[f]["jobs"][jid], "docs_only")
gate("image-e2e.yml", "journeys", docs["image-e2e.yml"]["jobs"]["journeys"], "journeys")
gate("job-yaml-lint.yaml", "lint", docs["job-yaml-lint.yaml"]["jobs"]["lint"], "yaml")
gate("action-lint.yaml", "actionlint", docs["action-lint.yaml"]["jobs"]["actionlint"], "workflows")

# What a docs-only change still runs: these never wait on the classifier.
for f in ("checks.yml", "job-pr-checks.yaml", "job-label-checker.yaml"):
    for jid, job in docs[f]["jobs"].items():
        if "changes" in str(job.get("needs", "")) or "needs.changes" in str(job.get("if", "")):
            bad(f"{f} {jid} waits on the changes job; a docs-only change must still run it")

# Only a pull request is classified; everything else runs in full.
ch = docs.get("changes.yml")
if not ch:
    bad("no .github/workflows/changes.yml")
else:
    on = ch.get("on", ch.get(True))
    if list(on) != ["workflow_call"]:
        bad("changes.yml must be callable only (on: workflow_call)")
    outs = (on.get("workflow_call") or {}).get("outputs") or {}
    for o in ("docs_only", "yaml", "workflows", "journeys"):
        if o not in outs:
            bad(f"changes.yml doesn't output {o}")
    run = yaml.safe_dump(ch["jobs"])
    if "build/ci/changes.sh" not in run or "github.event_name" not in run:
        bad("changes.yml doesn't classify through build/ci/changes.sh with the event name")
sys.exit(1 if fail else 0)
PY

[ "$fail" = 0 ] || exit 1
echo "PASS: a docs-only pull request runs only the scrub, PR Checks and the label checker; anything else runs everything"
