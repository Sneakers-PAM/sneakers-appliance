# The OS audit log

The program's audit service runs in k0s and may be down exactly when the OS layer matters, so the
OS layer keeps its own log in `/var/lib/sneakers/os-audit/` on the encrypted state volume.

## The log

One file per UTC day, `log-<YYYY-MM-DD>.jsonl`, mode 0600, rolling over to the day's next part
(`log-<YYYY-MM-DD>.p0001.jsonl`, `.p0002` and so on) when a file reaches 16 MiB
([Rotation and the archive](#rotation-and-the-archive)). Each line is one entry:

| Field | Meaning |
|---|---|
| `time` | when, in UTC |
| `actor` | the admin's name, or `console` |
| `keyFp` | the SHA-256 fingerprint of the key that signed in |
| `source` | the client address |
| `action`, `target` | what was done, to what; the target is named in words (see below) |
| `outcome` | `ok`, `refused`, or a reason (`exit`, `time-box`, `terminated`, `expired`, `done`, `idle`, `attempts`) |
| `code` | the error symbol when refused |
| `detail` | action-specific fields |
| `prev` | the hex SHA-256 of the line before, across day files |

The target is always something an admin reads, never an id: an admin's name, `network`, `box`,
`product`, a certificate by its names (`certificate *.example.org`, kept from before a removal), a
CSR by the names it asks for, a session as `alice's browser session from 192.0.2.20` (or `SSH
session`, `root shell`, `SSH login`), a root shell or its recording by admin and time (`alice's root
shell, asked for 2026-10-08 14:05 UTC`), an upload as `uploaded file` and a staged update as
`release <version>`, a recovery key by its label, and `factory reset`. The id the action concerns
stays in `detail`, under a key naming it: `certificate`, `csr`, `session`, `login`, `request` (a
root shell), `recording`, `upload`, `reset`, `change` (a network change), `fingerprint` or `key`.
Tests fail on any entry whose target looks like an id (`internal/osaudit/audittest`).

Every line is fsynced before the action it records is reported done. Init and accessd both append
to the log: each takes an flock on `.lock` in the log directory and reads the head again when the
other has written since, so the two keep one chain. A clock stepped back (an NTP
correction on a box that booted with the wrong time) keeps appending to the newest file, so the
files always read in chain order.

Verification walks every file oldest first and checks each `prev`. A changed, removed or reordered
line breaks the chain at the next line. The newest line has no successor on the box; once the
platform is up, spec 3 forwards new entries to sneakers-audit and records the last forwarded hash,
which covers it.

## Rotation and the archive

Rotation never breaks the chain. A part's first line is `os-audit.rotate`, written by the log
itself (actor `os-audit`): `detail.previous` names the file before it, `detail.previousLines` and
`detail.previousSha256` are that file's line count and the SHA-256 of its bytes (uncompressed). It
chains to the file before it like any line, and verification also checks the recorded count and
hash against that file while it's on the box, so a file cut down to its last line, which would
still chain, fails too.

The disk cleanup ([disk-layout.md](disk-layout.md#keeping-the-disk-from-filling)) compresses every
closed file (all but the newest) to `.jsonl.gz`: written beside it, read back and compared, then the
plain file goes. A file there both ways (a compress cut off before the plain one went) is read
plain, and the next run redoes it. Verification, the Logs page and the export read the compressed
files as they were written.

Nothing is dropped without a warning first. The archive (the closed files) is held to 5% of the
state volume, at least 512 MiB, and 2000 files. When it's over, its oldest files are flagged (in
`.archive-flags.json`), and Status warns (`WARNING_KIND_AUDIT_ARCHIVE`) with how many, from which
day and when they move, so an admin can export the log first. A day after a file was flagged it is
copied to the backup volume's `os-audit-archive/`, synced and compared byte for byte, and only then
removed here; the move is one `os-audit.archive.export` entry (`detail.files`, `detail.bytes`,
`detail.first`, `detail.last`, `detail.to`). A file that can't move stays, still flagged. The oldest
line left anchors the chain, as after retention pruning.

## Session recordings

An elevated session is recorded in full, both directions, as asciicast v2 in
`sessions/<request id>.cast`. As the file grows, the SHA-256 of every 64 KiB is written to the log
(`recording.chunk`, with the chunk's index, size and hash), and `recording.end` closes it with the
chunk count and why the session ended (`detail.reason`). Both have the outcome `ok`, like every
entry that isn't a refusal. Both name the recording by admin and start time and carry the request id in
`detail.recording`, which is what verification matches on. A session killed mid-way still leaves a prefix that verifies; a recording with more
than a chunk of unlogged bytes, or bytes after its end, doesn't. Only owners can view recordings.

## Sign-in, lockout and the root shell

| Action | By | When |
|---|---|---|
| `signin.password` | accessd | a :8443 sign-in with the name, password and TOTP code (or a refusal) |
| `signin.step-up` | accessd | a fresh TOTP code for a sensitive action |
| `access.lockout`, `access.throttle` | accessd | an account locks after 3 failures, or a source is held off after 10 |
| `access.admin.unlock` | accessd | an owner unlocks an account |
| `ssh.login`, `ssh.logout` | accessd | the closed shell's TOTP check, and its end |
| `ssh.login` (`refused`, `ACCESS_KEY_NO_CERTIFICATE`) | sneakers-sshd-run | a box-issued key sent without its certificate, read from sshd's log ([ssh-and-elevation.md](ssh-and-elevation.md#a-key-without-its-certificate)) |
| `setup.code.redeem`, `setup.code.reset` | accessd | a browser redeems the setup code (or a wrong one), the console asks for a new code |
| `recover-access.code`, `recover-access.cancel` | accessd | the console's Recover access code |
| `rootshell.begin`, `rootshell.code.issue`, `rootshell.open`, `rootshell.end` | accessd | the root shell's challenge, code, opening and end; `rootshell.end` is `ok` with how it ended in `detail.reason` (`exit`, `idle`, `time-box`, `terminated`) |
| `product.value.read` | accessd | an admin reads a value the product exposes (`<product> <name>` or `ProductService.GetExposedValue`): `detail.name`, `detail.state` `shown` or `consumed`; never the value ([ssh-and-elevation.md](ssh-and-elevation.md#product-values)) |
| `mcp.set` | accessd | an admin sets the product's MCP and machine API switches (the MCP card on :8443, or `<product> mcp on\|off` with the `ssh` surface): `detail.mcp`, `detail.machineApi` `on` or `off`; `ok` only once the product is ready with the change, else refused with `PRODUCT_NOT_READY` ([ssh-and-elevation.md](ssh-and-elevation.md#the-mcp-switch)) |
| `disk.alert.start`, `disk.alert.clear` | accessd (the disk guard) | a volume reaches 80% (`detail.level` `warning`) or 90% (`critical`), or drops 5 points below the level (`detail.level` the level that cleared, `detail.now` the new one), with `detail.volume`, `detail.percent`, `detail.used` and `detail.total` ([disk-layout.md](disk-layout.md#alerts-and-warnings)) |
| `disk.cleanup.run` | accessd (the disk guard) | every cleanup run, by itself (actor `disk-guard`) or for an admin: `detail.trigger` `timer`, `alert` or `admin`, `detail.freed` and `detail.freed.<step>`; outcome `partial` when a step failed (`detail.error.<step>`) |
| `disk.cleanup` | accessd | an admin asks for the cleanup (Clean up now on :8443, or `disk cleanup`): `detail.freed` |
| `os-audit.rotate`, `os-audit.archive.export`, `os-audit.prune` | the log itself | a file rolls over, archived files move to the backup volume ([Rotation and the archive](#rotation-and-the-archive)), or a file past retention is removed once archived ([Retention](#retention)) |
| `clock.step` | netd | SNTP stepped the clock (`detail.server`, `detail.offsetMs`, `detail.at`: `boot` or `running`); small offsets are slewed and not audited ([network.md](network.md#dns-ntp-and-the-host-name)) |

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
Pruning runs once a day; the oldest line left anchors the chain. A log file is never dropped
silently: before one past retention leaves the box's log directory, the archive on the backup
volume (`backup/os-audit-archive/`) must hold it byte for byte. When it doesn't, the file is copied
there, synced and read back first. Each removal is one `os-audit.prune` entry: `detail.file`,
`detail.sha256` and `detail.lines` (its bytes uncompressed), `detail.lastLineSha256` (its chain
link, the hash the next file's first line chains to), `detail.reason` (`retention: older than <n>
days`), `detail.archived` (the copy) and `detail.copied` (`yes`, or `no` when the archive already
had it). A file the archive can't take (the backup volume full or missing, or a different file of
that name there) stays where it is, and Status warns (`WARNING_KIND_AUDIT_ARCHIVE`) until the next
prune can archive it. Spec 4's retention applies to the
copies in backups.
