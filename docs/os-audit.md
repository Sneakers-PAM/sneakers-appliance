# The OS audit log

The program's audit service runs in k0s and may be down exactly when the OS layer matters, so the
OS layer keeps its own log in `/var/lib/sneakers/os-audit/` on the encrypted state volume.

## The log

One file per UTC day, `log-<YYYY-MM-DD>.jsonl`, mode 0600. Each line is one entry:

| Field | Meaning |
|---|---|
| `time` | when, in UTC |
| `actor` | the admin's name, or `console` |
| `keyFp` | the SHA-256 fingerprint of the key that signed in |
| `source` | the client address |
| `action`, `target` | what was done, to what |
| `outcome` | `ok`, `refused`, or a reason (`exit`, `time box`, `terminated`) |
| `code` | the error symbol when refused |
| `detail` | action-specific fields |
| `prev` | the hex SHA-256 of the line before, across day files |

Every line is fsynced before the action it records is reported done. Init and accessd both append
to the log: each takes an flock on `.lock` in the log directory and reads the head again when the
other has written since, so the two keep one chain. A clock stepped back (an NTP
correction on a box that booted with the wrong time) keeps appending to the newest file, so the
files always read in chain order.

Verification walks every file oldest first and checks each `prev`. A changed, removed or reordered
line breaks the chain at the next line. The newest line has no successor on the box; once the
platform is up, spec 3 forwards new entries to sneakers-audit and records the last forwarded hash,
which covers it.

## Session recordings

An elevated session is recorded in full, both directions, as asciicast v2 in
`sessions/<request id>.cast`. As the file grows, the SHA-256 of every 64 KiB is written to the log
(`recording.chunk`, with the chunk's index, size and hash), and `recording.end` closes it with the
chunk count. A session killed mid-way still leaves a prefix that verifies; a recording with more
than a chunk of unlogged bytes, or bytes after its end, doesn't. Only owners can view recordings.

## Reboot and shutdown

Reboot and shutdown are graceful by default on both the console and :8443: the stack drains before
the box stops. A forced reboot or shutdown skips the drain and needs a second, explicit
confirmation. Either way the entry records who asked, where from and how:

| Field | Value |
|---|---|
| `action` | `power.reboot` or `power.shutdown` |
| `actor`, `keyFp`, `source` | the admin, the key that signed in and the client address, or `console` |
| `detail.surface` | `console` or `8443` |
| `detail.mode` | `graceful`, or `forced` after the second confirmation |

Init writes its own entries for the same request with `detail.surface` `init`: the caller
(`detail.caller` `osadmin` or `shell`, its `uid` and `pid`), `outcome` `accepted` when it takes the
request, then `ok` (or `drain-failed`) before it syncs and acts, or `refused` with the code. The
factory reset adds `power.factory-reset.arm`, `.cancel` and `.run` from init
([factory-reset.md](factory-reset.md)).

## Retention

The log keeps 400 days and recordings 90 days by default, both settable on the Logs and audit page.
Pruning runs once a day; the oldest line left anchors the chain. Spec 4's retention applies to the
copies in backups.
