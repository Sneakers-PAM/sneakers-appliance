# The access store

Every way into the box (the closed shell, :8443 and elevation) traces back to an SSH public key
enrolled in the access store. accessd owns it; nothing else writes it.

## The file

`/var/lib/sneakers/access/store.json`, mode 0600, on the encrypted state volume. Each write bumps
`version`, goes to `store.json.tmp`, is fsynced, renamed into place and the directory fsynced, so a
power cut leaves either the old or the new version, never half of one. A leftover `.tmp` file is
discarded when the store opens.

```json
{
  "version": 7,
  "nextUid": 20001,
  "admins": [
    {
      "name": "alice", "uid": 20000, "role": "owner",
      "created": "2026-10-05T14:00:00Z", "createdBy": "console",
      "keys": [
        { "fingerprint": "SHA256:...", "type": "ssh-ed25519", "publicKey": "ssh-ed25519 AAAA...",
          "comment": "alice laptop", "added": "...", "addedBy": "alice", "via": "enrol" }
      ],
      "approvalHoldUntil": null
    }
  ],
  "recoveryKeys": [
    { "fingerprint": "SHA256:...", "type": "ssh-ed25519", "publicKey": "ssh-ed25519 AAAA...",
      "label": "offline safe", "set": "...", "setBy": "alice" }
  ],
  "elevationPolicy": { "maxMinutes": 240, "defaultMinutes": 60, "selfApprovalWhenSingleOwner": true }
}
```

Admin uids count up from 20000 and are never reused, so a removed admin's files can't be inherited
by a new one. `via` is one of `enrol`, `shell`, `osadmin`, `url`, `typed` or `console-recovery`.

## Key rules

| Kind | Accepted | Refused |
|---|---|---|
| Login key | `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `sk-ssh-ed25519`, `sk-ecdsa-sha2-nistp256`, `ssh-rsa` of 3072 bits or more | DSA and shorter RSA (`ACCESS_KEY_WEAK`), anything else (`ACCESS_KEY_TYPE`) |
| Recovery key | `ssh-ed25519`, `ssh-rsa` of 3072 bits or more | `sk-` keys, which can sign but not decrypt, and ECDSA (`ACCESS_KEY_TYPE`); DSA and shorter RSA (`ACCESS_KEY_WEAK`) |

A pasted line may carry `authorized_keys` options; they are dropped, and the stored `publicKey`
holds only the type and the key.

## Invariants

Checked on every write. A write that breaks one is refused with its code and nothing changes.

- Admin names match `^[a-z][a-z0-9_-]{1,30}$`, are unique, and aren't a system account: `root`,
  `maint`, `enrol`, `sshd`, `sshkeys`, `nobody`, `osadmin` (`ACCESS_NAME`).
- A key belongs to one admin; no login key equals a recovery key; no two recovery keys are equal
  (`ACCESS_KEY_DUPLICATE`).
- At most three recovery keys (`ACCESS_RECOVERY_KEY_LIMIT`).
- Once the first-admin step is done: at least one owner (`ACCESS_LAST_OWNER`) with at least one key
  (`ACCESS_LAST_KEY`). Add the new key before removing the old one.
- Once the recovery key step is done: at least one recovery key (`ACCESS_LAST_RECOVERY_KEY`).

Writes are serialized, and each one runs on the state the previous one left, so two sessions
removing the last two keys at once can't both succeed.

## Unix accounts

`/etc` is read-only in the root image, so `/etc/passwd`, `/etc/group` and `/etc/shadow` are symlinks
(`os/rootfs/etc/`) into `/run/sneakers/accounts/`. accessd renders the three files from the store at
start and after every change, each through a tmp file and a rename.

| Account | uid | Shell | Notes |
|---|---|---|---|
| `root` | 0 | `/usr/sbin/nologin` | no login: no keys, no password |
| `maint` | 0 | `/usr/libexec/sneakers-elevated` | the elevation account; only a short-lived certificate reaches it |
| `sshd` | 100 | `/usr/sbin/nologin` | OpenSSH privilege separation |
| `sshkeys` | 101 | `/usr/sbin/nologin` | runs the enrolment keys command |
| `osadmin` | 102 | `/usr/sbin/nologin` | the unprivileged :8443 server |
| `enrol` | 103 | `/usr/libexec/sneakers-enrol` | rendered only while an enrolment window is open |
| `nobody` | 65534 | `/usr/sbin/nologin` | |
| each admin | 20000 and up | `/usr/bin/sneakers-shell` | home `/run/sneakers/home/<name>`, empty and root-owned |

Every account's shell is its forced command, so sshd never passes a line to `/bin/sh`. Every
`/etc/shadow` entry is `*`: no account has a password, so none can be set or guessed.

## The :8443 sign-in

`sneakers-osadmin` serves the appliance admin on port 8443 of the management addresses only. The
browser never takes a password or a key; the admin's SSH key vouches for it.

1. The sign-in page asks for a code (`SignInService.BeginSignIn`) and shows it, `XXXX-XXXX`, with the
   source address and browser the box sees. A code lasts 5 minutes and works once; at most 64 wait
   at a time.
2. The admin runs `ssh alice@<address> login XXXX-XXXX`. The closed shell shows the browser's address
   and user agent and asks to confirm, then calls `LocalService.ApproveSignIn` on
   `/run/sneakers/osadmin.sock` with the admin and the fingerprint of the key that signed in. The
   approval is refused when the key isn't that admin's or an admin uid approves as someone else.
3. The waiting page (`PollSignIn`) gets the session cookie and its CSRF token.

The approval and the session start are both written to the OS audit log (`signin.approve`,
`signin.session.start`).

### Sessions

| Rule | Value |
|---|---|
| Cookie | `__Host-osadmin-session`: `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, no `Domain` (host-only) |
| CSRF | the session's token in `X-CSRF-Token` on every call that changes something |
| Idle timeout | 15 minutes; every call moves it |
| Absolute limit | 8 hours |
| Per admin | at most 5; a sixth sign-in ends the oldest |
| Storage | memory only: a restart of `sneakers-osadmin` signs everyone out |

A session is bound to its admin and key. Every call checks both still exist, so removing a key ends
the sessions it signed in, and removing an admin ends all of theirs. A role change applies to live
sessions at once.

### Roles and step-up

| Role | Can |
|---|---|
| `owner` | everything, including admins, roles, the elevation policy, the recovery keys, setup and Secure Boot |
| `admin` | every page and action except managing other admins and the owner-only actions; manages their own keys |

The first admin is an owner, and the last owner can't be demoted or removed (`ACCESS_LAST_OWNER`).

Sensitive actions need a sign-in from the last 5 minutes (`ACCESS_STEPUP_REQUIRED`): adding or
removing admins and keys, roles, the elevation policy, the network settings, the recovery keys,
finishing setup, the Secure Boot setting and power actions. The page asks for a fresh code; the new
session replaces the old one in that browser. [osadmin-api.md](osadmin-api.md) lists the role,
step-up and audit action of every method.

## The Setup page

On first boot, after the first admin's key is enrolled, the Setup page finishes the appliance setup:

- **Recovery keys,** one to three (`ssh-ed25519`, or `ssh-rsa` of 3072 bits or more). Each change asks
  init for a new escrow encrypted to the whole set and writes it to
  `/var/lib/sneakers/backup/escrow/escrow-<time>.age`; when the escrow fails, the keys don't change.
  The newest escrow can be downloaded from the page.
- **The single-admin warning.** With one admin there is no quorum, so a factory reset means deleting
  and re-creating or re-flashing the box. The operator confirms the warning, or adds a second admin,
  before Finish.
- **Finish** checks every step (`SETUP_INCOMPLETE` names the open one), writes
  `/var/lib/sneakers/setup/done` and links to the product's own `/setup`, which runs once the
  platform is up. After setup the last recovery key can't be removed (`ACCESS_LAST_RECOVERY_KEY`).

## Status, Network, Logs and Power

- **Status:** the version and slots, the protection level and custody mode, the management
  addresses, the state volume's use and daily growth, the :8443 certificate, and the warnings:
  exposure (a public management address with an allow-list open to any source), reduced protection,
  the self-signed certificate, an unsynced clock, and a key added with the console's Recover access.
  The Secure Boot setting is changed here (owner, step-up, the host name typed to confirm).
- **Network:** reads and changes netd's settings. A change is undone unless `ConfirmNetwork` comes
  within 120 seconds from a session that still works.
- **Logs and audit:** the OS audit log, newest first, filtered by action, with its chain state, and the
  whole log as a download.
- **Power:** reboot and shut down, graceful by default; the page lists the signed-in sessions first.
  Init drains the services, audits, syncs and unmounts before it acts ([factory-reset.md](factory-reset.md)).
  A forced reboot or shutdown skips the drain and needs a second, explicit confirmation
  (`POWER_FORCED_CONFIRM` without it); the audit entry records `mode` as `graceful` or `forced`.

## The factory reset quorum

A factory reset from :8443 needs a quorum of appliance admins, M of N, never one person.

- **The roster** is set on the Access page (owner, step-up): N admins and the threshold M, from 2 to
  N. Unset, it is every admin with two approvals. Members who are later removed drop out and the
  threshold drops with them, so the quorum keeps working after an admin leaves.
- **With a single admin there is no quorum and no factory reset.** The Power page says so; the way
  back is to delete and re-create, or re-flash, the box (`RESET_UNAVAILABLE`).
- **Start** (owner, step-up, the host name typed to confirm) opens a request. The starter's approval
  counts once when they are on the roster; approving again is refused (`RESET_APPROVED`).
- **Approve** (a roster member, step-up). A request without its quorum after 30 minutes expires.
- **The delay.** The last approval starts a 10-minute countdown, shown on Status. Any admin may
  cancel it on :8443, and the console (or a closed-shell login, as itself) through
  `LocalService.LocalCancelFactoryReset`. The request lives in memory only, so a reboot or a
  restart of `sneakers-osadmin` cancels it too.
- **Init checks it too.** The last approval arms init (`Power.ArmFactoryReset`), which checks the
  approvals against the access store's roster itself; if it refuses (`RESET_QUORUM`), the approval
  isn't counted and no countdown starts. A cancel reaches init as well.
- **Then** osadmin asks init's `Power.FactoryReset` to run the armed request. Init runs it only after
  its own delay, if nothing cancelled it ([factory-reset.md](factory-reset.md)).

Every step is in the OS audit log: `power.factory-reset.start`, `.approve`, `.cancel`, `.expire` and
`.run`.

## Running sneakers-osadmin

`sneakers-osadmin` reads the management addresses and host name from netd, makes or reuses its
certificate in `/var/lib/sneakers/osadmin/`, and listens on each address's port 8443; when netd
reports new addresses or a new host name it rebinds with a matching certificate, keeping the
sessions. Until accessd lands it opens the access store and the OS audit log itself. Flags:
`--state` (`/var/lib/sneakers`), `--assets` (`/usr/share/sneakers/osadmin`), `--init-socket`,
`--netd-socket` and `--socket` (`/run/sneakers/osadmin.sock`). `LOG_LEVEL` and `LOG_FORMAT` set the
logging; the defaults are `error` and JSON.
