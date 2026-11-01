# The support bundle

One command, one file, everything needed to diagnose a box, in the spirit of a Cisco
`show tech-support`. The box runs a fixed, versioned set of read-only commands, redacts every line
before it's written, and puts them under one UTC timeline. The base owns the framework (the runner,
the format, the redaction, the outputs and the audit entry) and its own sections; a product adds its
own in `product.yaml`, and the base names none of them. The code is `internal/supportbundle`.

## Getting one

| From | How | What you get |
|---|---|---|
| SSH, short form | `support-bundle` | the key sections, with tails of about 50 lines, to copy out of the terminal |
| SSH, full form | `support-bundle full` | every section, with tails of 2000 lines |
| SSH, to a file | `ssh admin@box1.sneakers.example.org support-bundle full > support-bundle.txt` | the full form, plain |
| :8443 | `GET /export/support-bundle` (the Logs page's **Download support bundle**) | the full form, as `support-bundle-<host>-<UTC time>.zip`, a zip holding the one file `support-bundle-<host>-<UTC time>.txt` |

Any admin may take one, and each is audited as `support.bundle`
([os-audit.md](os-audit.md)). One runs at a time; a second is refused until the first ends, so a
box in trouble isn't asked to do it twice.

Over SSH the text is plain: labelled sections, no pager, no binary or tar stream, so it selects and
copies cleanly in PuTTY, MobaXterm and OpenSSH. On a terminal the headings, errors and warnings are
in colour, and copying a selection leaves the colour behind; `--no-color` turns it off. Anything that
isn't a terminal, and every :8443 download, has no escape codes at all.

The :8443 download is a `.zip` because macOS and Windows both open one with no extra tools. It's
Deflate at the best compression, and it isn't encrypted, since every line is already redacted. The
text inside is the same format as over SSH.

The zip is streamed as the bundle is written, a section at a time, and it's always closed, so a
bundle stopped by its time or size limit, or by its request ending, still opens, with what was
written and without the rest. Read the text's last line to tell: a file with no `##### end` line was
cut off. A connection that drops part way is different: the end of the zip never arrives, so the
browser reports a failed download, and any partial file it keeps won't open. Take the bundle again,
or over SSH.

A bundle that's refused, because another is running, is a plain-text `503` with no zip.

## The format

This is the contract for anything that reads a bundle, the help assistant among them. A change a
reader must know about bumps `bundle-format`.

```text
##### support-bundle
bundle-format: 1
form: full
box: box1.sneakers.example.org
version: 0.1.0
product: Sneakers
started: 2026-10-30T16:00:00Z

##### 1. status
# started: 2026-10-30T16:00:00Z
{ ...the section's output... }
# ended: 2026-10-30T16:00:01Z result: ok

==== Product: Sneakers ====

##### 30. The Sneakers workloads
# started: 2026-10-30T16:00:41Z
...
# ended: 2026-10-30T16:00:42Z result: ok

##### 41. timeline
# started: 2026-10-30T16:00:50Z
2026-10-30T12:00:01.000Z [k0s] prepare starts
2026-10-30T12:00:02.000Z [pods] [pod/sneakers-gateway-0/gateway] listening
# ended: 2026-10-30T16:00:50Z result: ok

##### end sections=41 failed=0 truncated=0
```

| Line | Pattern | Meaning |
|---|---|---|
| File start | `##### support-bundle`, then `key: value` lines up to a blank line | `bundle-format`, `form` (`short` or `full`), `box`, `version`, `product` and `started`, the bundle's start in UTC. `box` and `product` are left out when unknown. |
| Section heading | `^##### (\d+)\. (.*)$` | the section's number and the command it ran |
| Group heading | `^==== Product: (.*) ====$` | what follows is the product's own |
| Section start | `^# started: (\S+)$` | the section's start in UTC |
| Section end | `^# ended: (\S+) result: (.*)$` | the end, and how it went (below) |
| Skipped section | `^# skipped: (.*)$` | in place of the start and end lines: `the bundle's time limit` or `the bundle's size limit` |
| Container start | `^--- (ns)/(pod)/(container)$` | inside a pod log section |
| File end | `^##### end sections=(\d+) failed=(\d+) truncated=(\d+)$` | the bundle ran to its end; a file without it was cut off |

The `result` is one of `ok`; `absent` (there's nothing there, such as a log that hasn't rotated yet);
`failed: <why>`; `timed out after <bound>`; or `truncated at <n> bytes`. A section that fails is noted
and the next one runs. A section's output can itself contain lines that start with `#`, so read
headings by the patterns above.

### Times

Every time the bundle writes is UTC. Each line of a log section that carries a time is rewritten to
start with it, as `2006-01-02T15:04:05.000Z` (one width, so the lines also sort as text). The time
comes from a time at the start of the line (`kubectl --timestamps`, k0s-interim's record), a `time`,
`ts` or `timestamp` field (JSON, logrus, logfmt), an epoch `ts` (zap), klog's `Lmmdd hh:mm:ss` or Go's
`log` package. A time with no zone is the box's, which runs in UTC. A line with no time in it stays
as it is and isn't on the timeline.

The last section, `timeline`, merges every log section by time: `<time> [<source>] <line>`, where the
source is `box`, `k0s`, `pods`, `audit` or `product`. It keeps the newest 5000 lines (50 in the short
form), each cut at 400 bytes.

## What's in it

| Section | Short | Full |
|---|---|---|
| Status, box-values, `uname -a`, `uptime` | yes | yes |
| `k0s status`, `kubectl get nodes`, `get all`, `get events` | yes (last 50 events) | yes |
| `kubectl describe nodes`, `describe pods` | no | yes |
| Pod logs | containers not ready or restarted | every container |
| Pod logs, `--previous` | restarted containers | restarted containers |
| `console.log`, k0s's `prepare.log` | yes | with `console.log.1` and `prepare.log.1` |
| `upgrade-progress.json`, the OS audit tail | yes | yes |
| `mount`, `df -h`, `ls -laR --full-time` of k0s's manifests, `phase-placed`, `switches`, `ps w` | yes | yes |
| `free`, `ip addr`, `ip route`, `dmesg` | no | yes |
| Secret names, env var names | yes | yes |
| The product's sections | those marked `short` | all |
| The merged timeline | yes | yes |

Every OS command runs through the image's own busybox, with no shell; a test holds each applet and
option to `build/busybox/busybox.config`. Every cluster command is a `get`, `describe` or `logs`.

### Bounds

| | Short | Full |
|---|---|---|
| A section's output | 256 KiB | 32 MiB |
| The whole bundle | 4 MiB | 200 MiB |
| The whole run | 2 minutes | 10 minutes |
| A section | 20 s, the cluster's 30 s, the pod logs 3 minutes (each log 10 s) | the same |

A section past its size is stopped and marked `truncated`. Past the bundle's size or time, the rest
are listed as skipped, and the timeline still comes last.

## Redaction

Secrets, tokens and keys are removed from every line before it's written; the only way into the file
is through the redactor, in every form. What it removes:

- `snk_` tokens, JWTs, GitHub tokens and age secret keys, wherever they appear;
- PEM private keys, on one line or many. A key with no END line withholds the rest of its section, so
  it fails closed;
- bearer and basic credentials, and the whole value of `Authorization`, `Cookie`, `Set-Cookie`,
  `X-Api-Key` and similar headers;
- URL passwords, an empty user's (`redis://:<password>@`) too;
- the value of any `key=value`, `key: value` or JSON field whose key says it's secret: `password`,
  `secret`, `token`, `api_key`, `credential`, `kek`, `enc_key`, `signature` and the like, in any
  case and with any prefix or suffix. A key that only names a secret (`secretName`, `token_type`) is
  kept, since the name helps a diagnosis;
- the values a `describe` prints under `Environment:`, so only the names stay, and the
  `last-applied-configuration` annotation, which repeats the manifest;
- every value the box made or was given for the product (its box secrets, the email password), by
  value, so one with nothing around it that says it's secret goes too.

A line longer than 64 KiB is withheld whole, and terminal escapes and control characters are taken
out, so a log can't act on the terminal it's read in. Masked values read `[redacted]`.

Secrets and env vars are names only. `kubectl get secrets -A` is the plain table, whose rows the API
server sends with no data in them, and the env names come from a `custom-columns` read of the names
alone. The bundle never asks for a Secret or a whole object (`-o yaml`, `-o json`), and a test holds
every cluster command to that.

## A product's sections

A product declares its sections in `product.yaml` ([release.md](release.md#productyaml)):

```yaml
support:
  - title: The workloads
    kubectl: {verb: get, resource: deployments, namespace: acme}
    short: true
  - title: The gateway's log
    kubectl: {verb: logs, namespace: acme, selector: app.kubernetes.io/component=gateway, tail: 300}
    timeout: 30s
    short: true
    redact: ['acct-[0-9]+']
  - title: The size of the database
    command: du -s -h /var/lib/sneakers-data/pgha
```

| Field | Meaning |
|---|---|
| `title` | one line, unique; the section's heading, under `Product: <name>` |
| `command` | a busybox applet and its options, split on spaces; or |
| `kubectl` | a read, by its parts: `verb` (`get`, `describe` or `logs`), `resource`, `namespace`, `selector`, and for logs `previous` and `tail` (up to 5000; the default is the form's own) |
| `timeout` | a duration up to 60s; 15s by default |
| `redact` | more RE2 patterns to mask here; they add to the base's redaction and can't turn any of it off |
| `short` | put it in the short form too; every section is in the full form |

They're checked when the bundle is built and again when the box reads them, by the same code
(`internal/productspec/support.go`): a bundle that breaks a rule doesn't build. A section has to be
read-only, bounded and busybox-safe:

- **Commands:** one of `cat`, `df`, `du`, `free`, `head`, `ls`, `tail`, `uptime` and `wc`, with only
  the options that applet is allowed, one option a word, no shell characters and nothing run through a
  shell. Paths are clean and under `/var/lib/sneakers-data`, the product's own data.
- **`get` and `describe`:** only the resources in `supportResources`. Secrets and ConfigMaps aren't
  among them. `describe` needs a namespace.
- **`logs`:** a namespace and a label selector.
- At most 32 sections.

A log from `kubectl logs` joins the timeline under `product`. The Sneakers sections are in
`build/product/sneakers/product.yaml`.
