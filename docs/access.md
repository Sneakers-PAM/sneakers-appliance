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
  "elevationPolicy": { "maxMinutes": 240, "defaultMinutes": 60, "selfApprovalWhenSingleOwner": true },
  "revokedKeys": [
    { "fingerprint": "SHA256:...", "publicKey": "ssh-ed25519 AAAA...", "admin": "bob", "revoked": "...",
      "revokedBy": "alice" }
  ]
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
  `maint`, `enrol`, `sshd`, `sshkeys`, `nobody`, `osadmin`, `console` (`ACCESS_NAME`).
- A key belongs to one admin; no login key equals a recovery key; no two recovery keys are equal
  (`ACCESS_KEY_DUPLICATE`).
- At most three recovery keys (`ACCESS_RECOVERY_KEY_LIMIT`).
- Once the first-admin step is done: at least one owner (`ACCESS_LAST_OWNER`) with at least one key
  (`ACCESS_LAST_KEY`). Add the new key before removing the old one.
- Once the recovery key step is done: at least one recovery key (`ACCESS_LAST_RECOVERY_KEY`).

Writes are serialized, and each one runs on the state the previous one left, so two sessions
removing the last two keys at once can't both succeed.

## Removed keys are revoked

A login key that leaves the store, removed on its own or with its admin, by any surface (the page,
the closed shell, the console), goes on `revokedKeys` in the same write, with its admin, the time
and who removed it (`revokedBy`: the admin on the page or in the closed shell, or `console`). A key
revoked before the store recorded this has no `revokedBy`, and `ListAdmins` reports it as
`unknown`. While it's there:

- it is on sshd's revocation list, `/var/lib/sneakers/ssh/revoked.krl`, as an explicit key, so sshd
  refuses it (and any certificate for it) even if a stale `authorized_keys` file still lists it.
  The list is written inside the store's write, before the store file is replaced: when the list
  can't be written the change is refused and the key stays, so a key is never out of the store and
  still accepted. accessd writes the list from the store again when it starts;
- adding it to any admin is refused (`ACCESS_KEY_REVOKED`);
- the :8443 sessions it signed in end, and so does an elevated shell it opened (an approved,
  unused elevation certificate for it is revoked).

An owner takes a key off the list with `AccessService.UnrevokeKey` (step-up, audited as
`access.key.unrevoke`); `ListAdmins` returns the revoked keys, each with
`revoked_by`. Only then can the key be added again.

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

`sneakers-osadmin` serves the appliance admin on port 8443 of the management addresses only, and
forwards every call to accessd, which holds the codes and sessions and decides
([accessd](#accessd)). The browser never takes a password or a key; the admin's SSH key vouches
for it.

1. The sign-in page asks for a code (`SignInService.BeginSignIn`) and shows it, `XXXX-XXXX`, with the
   source address and browser the box sees. A code lasts 5 minutes and works once; at most 64 wait
   at a time.
2. The admin runs `ssh alice@<address> login XXXX-XXXX`. The closed shell shows the browser's address
   and user agent and asks to confirm, then calls `LocalService.ApproveSignIn` on
   `/run/sneakers/access.sock` with the admin and the fingerprint of the key that signed in. The
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
| Storage | memory only, in accessd: a restart of `sneakers-accessd` signs everyone out (a restart of `sneakers-osadmin` doesn't) |

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
- **The first sign-in.** The first :8443 session started during setup is recorded
  (`/var/lib/sneakers/setup/signed-in`, `signedIn` on the setup state): it proves the admin can reach
  and use :8443 from where they sit.
- **Finish** (or the console's `Setup.Complete`, root only, which runs the same checks) checks every
  step (`SETUP_INCOMPLETE` names the open one: an owner with a key, a recovery key and its escrow, the
  single-admin warning, the first sign-in), writes `/var/lib/sneakers/setup/done` and links to the
  product's own `/setup`, which runs once the platform is up. The console confirms the single-admin
  warning with `SetupService.AcknowledgeSingleAdmin` (root only). After setup the last recovery key
  can't be removed (`ACCESS_LAST_RECOVERY_KEY`).

## Status, Network, Logs and Power

- **Status:** the version and slots, the protection level and custody mode, the management
  addresses, the state volume's use and daily growth, the :8443 certificate, and the warnings:
  exposure (a public management address with an allow-list open to any source), reduced protection
  (its reason and how to raise it, in the console's words), the self-signed certificate, an
  unsynced clock, and a key added with the console's Recover access.
  The Secure Boot setting is changed here (owner, step-up, the host name typed to confirm).
- **Network:** reads and changes netd's settings. A change is undone unless `ConfirmNetwork` comes
  within 120 seconds from a session that still works.
- **Logs and audit:** the OS audit log, newest first, filtered by action, with its chain state, and the
  whole log as a download.
- **Power:** reboot and shut down, graceful by default; the page lists the live sessions first
  (the :8443 browsers, the SSH logins and the elevated shells), and an owner can end any of them
  (step-up, audited as `session.end`; see [osadmin-api.md](osadmin-api.md)).
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
  `LocalService.LocalCancelFactoryReset`. The request lives in accessd's memory only, so a reboot or
  a restart of `sneakers-accessd` cancels it too.
- **Init checks it too.** The last approval arms init (`Power.ArmFactoryReset`), which checks the
  approvals against the access store's roster itself; if it refuses (`RESET_QUORUM`), the approval
  isn't counted and no countdown starts. A cancel reaches init as well.
- **Then** osadmin asks init's `Power.FactoryReset` to run the armed request. Init runs it only after
  its own delay, if nothing cancelled it ([factory-reset.md](factory-reset.md)).

Every step is in the OS audit log: `power.factory-reset.start`, `.approve`, `.cancel`, `.expire` and
`.run`.

## accessd

`sneakers-accessd` is the root service that owns access: the access store, the sign-in codes and the
:8443 sessions, the OS audit log, and the files rendered from the store. It also runs the :8443 API's
backend, so `sneakers-osadmin` runs as the unprivileged `osadmin` user and holds no session, key or
store. Both are in init's service table (`os/rootfs/services.d/`):

| Service | Runs as | Phases | Restart |
|---|---|---|---|
| `accessd` (`/usr/bin/sneakers-accessd`) | root | firstboot, normal | always |
| `osadmin` (`/usr/bin/sneakers-osadmin`) | `osadmin` (uid 102) | firstboot (on demand, at its setup step), normal | always, after accessd is ready |

### access.sock

accessd serves `/run/sneakers/access.sock` (mode 0666; the protos are
`proto/sneakers/appliance/access/v1/access.proto`). Every connection's peer is read with
`SO_PEERCRED`, and the peer uid is the caller's identity, never a field the client sends. Any other
uid is refused before a byte is read.

| Peer | Gets | As |
|---|---|---|
| root | every method of `AccessService`, `NetworkService`, `SetupService` and `ElevationService`, the console's `EnrolmentService` methods, and `LocalService` | the console (an owner named `console`), firstboot, or `sneakers-elevated` (the `maint` login is uid 0) |
| an admin uid (a closed-shell login) | the methods the shell needs: status, admins, keys, network show/set/confirm, the setup recovery key, elevation request/status/cert, and `LocalService` | that admin, with that admin's role |
| `osadmin` | the :8443 API (`sneakers.appliance.osadmin.v1`), the upload and the audit export, and `BindingService` | the signed-in admin of the session each call carries |
| `enrol` (uid 103) | `EnrolmentService.SubmitEnrolmentCode` and `GetEnrolmentKey` only | `sneakers-enrol`, during an enrolment window |

- The console-only methods (`AddRecoveryKey`, `ResetAllowList`, `Complete`, `ApproveElevation`,
  `DenyElevation`, `TerminateElevation`, `BeginElevatedSession`, `EndElevatedSession` and the
  console's enrolment methods, `OfferEnrolmentKey` and the Recover access window among them) refuse
  an admin uid with `ACCESS_FORBIDDEN`, even an owner's.
- A uid in the admin range with no admin behind it is refused (`ACCESS_FORBIDDEN`).
- A closed-shell login sends the fingerprint of the key sshd says signed it in
  (`Sneakers-Key-Fingerprint`) and its SSH client address (`Sneakers-Source`), for the audit entry.
  A fingerprint that isn't one of that admin's keys is refused.
- For `osadmin`, accessd checks the session cookie, the CSRF token, the role and the step-up of
  every call itself; a call with no valid session is `ACCESS_SESSION`. The browser's address comes
  from `Sneakers-Client-Address`, which accessd reads from the `osadmin` uid only.
- Every local call is checked against the same per-method role as on :8443 and written to the OS
  audit log with the `ssh` or `console` surface.

### What accessd renders

On start and after every change to the store, accessd writes:

- `/run/sneakers/accounts/{passwd,group,shadow}` and the empty homes under `/run/sneakers/home/`
  (the `enrol` account only while an enrolment window is open);
- `/run/sneakers/ssh/`: `sshd_config` (listening on netd's management addresses, link-local ones
  left out; enrol mode until an owner has a key, then admin mode, with the `enrol` block while a
  window is open), `authorized_keys/<admin>` and `principals/maint` (the `elev-<id>` principal of
  each approved, unused elevation certificate). It renders into a new directory, has the pinned sshd check it (`sshd -t`), and
  swaps it in whole; a config sshd refuses is never swapped in. When `sshd_config` changed (a new or
  removed admin, new addresses) it sends `sneakers-sshd-run` (the pid in `/run/sneakers/sshd.pid`) a
  `SIGHUP`, and sshd-run checks again before it tells sshd; a key change needs none, since sshd
  reads the key files at each login. See [sneakers-sshd-run](ssh-and-elevation.md#sneakers-sshd-run).

It renders again whenever an elevation is approved, used, revoked or expires, and when an enrolment
window opens or closes. It also creates `/var/lib/sneakers/osadmin/` owned by `osadmin` (the :8443 certificate) and the
root-only `/var/lib/sneakers/osadmin-api/` (the update policy, history and uploads, and the disk
samples).

### The update key

The `.bin` decryption key is read from the running UKI on each use, in accessd (root), and never
written to disk. The upgrades design gives it to `sneakers-upgraded`, which isn't on the box yet;
it moves there when that lands.

### When accessd is down

- Logins still authenticate: sshd uses the files accessd rendered, which stay in `/run`.
- The closed shell's accessd commands say the appliance services are unavailable, and `status`
  shows the last status accessd kept (`/run/sneakers/access/status.json`, refreshed every minute and
  on every status call) with the time it was taken.
- :8443 answers every call with Connect `unavailable` and the same sentence. Status, for a browser
  accessd accepted in the last 8 hours, gets the last status `sneakers-osadmin` saw (or the file),
  with an `accessd` health entry saying it's down.
- Init restarts accessd (`restart: always`).

Elevation and the enrolment window also live in accessd; see
[ssh-and-elevation.md](ssh-and-elevation.md#one-time-elevation). Every minute accessd expires
elevation requests and certificates whose time is up, ends the record of a session whose
`sneakers-elevated` is gone, and closes an idle enrolment window. While accessd is down no
elevation can start: `sneakers-elevated` needs accessd to use the certificate up first.

Flags: `--state` (`/var/lib/sneakers`), `--run` (`/run/sneakers`), `--socket`, `--init-socket`,
`--netd-socket`, `--esp` (`/run/sneakers/esp`) and `--sshd` (`/usr/sbin/sshd`).

## Running sneakers-osadmin

`sneakers-osadmin` runs as `osadmin` and refuses to run as root. It asks accessd for the management
addresses and host name (`BindingService.GetBinding`, from netd), makes or reuses its certificate in
`/var/lib/sneakers/osadmin/`, and listens on each address's port 8443; when the addresses or the host
name change it rebinds with a matching certificate. Port 8443 speaks TLS only: a browser that asks
for `http://<box>:8443/` gets a `301` to the same host, port and path over `https://`, with a short
"Redirecting you to https…" page and the link, and nothing else is served over plain HTTP. It serves the static pages and forwards the API,
`POST /upload` and `GET /export/audit-log` to accessd; `LocalService` is never forwarded. Flags:
`--state` (`/var/lib/sneakers`), `--assets` (`/usr/share/sneakers/osadmin`) and `--access-socket`
(`/run/sneakers/access.sock`). `LOG_LEVEL` and `LOG_FORMAT` set the logging; the defaults are
`error` and JSON.
