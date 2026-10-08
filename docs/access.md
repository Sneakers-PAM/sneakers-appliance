# The access store

The access store holds who may get in: the admins, their passwords and TOTP secrets, the SSH keys
the box issued them, the root-operator roster, the recovery keys and the access settings. accessd
owns it; nothing else writes it. Signing in to :8443 takes a name, a password and a TOTP code; an
SSH login takes a box-issued key and then a TOTP code ([ssh-and-elevation.md](ssh-and-elevation.md)).

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
      "created": "2026-10-07T14:00:00Z", "createdBy": "setup",
      "password": { "hash": "$argon2id$v=19$m=65536,t=3,p=4$...", "changed": "..." },
      "totp": { "sealed": "...", "added": "..." },
      "keys": [
        { "fingerprint": "SHA256:...", "type": "ssh-ed25519", "publicKey": "ssh-ed25519 AAAA...",
          "comment": "laptop", "added": "...", "addedBy": "alice", "via": "issued",
          "serial": 3, "validBefore": "2027-10-07T14:00:00Z", "certificate": "<OpenSSH ed25519 user certificate>" }
      ]
    }
  ],
  "recoveryKeys": [
    { "fingerprint": "SHA256:...", "type": "ssh-ed25519", "publicKey": "ssh-ed25519 AAAA...",
      "label": "offline safe", "set": "...", "setBy": "alice" }
  ],
  "quorum": { "members": ["alice"], "required": 1 },
  "accessPolicy": { "lockoutMode": "timed", "rootCodeMinutes": 10, "rootSessionMinutes": 10, "sshKeyValidDays": 365 },
  "nextSerial": 4,
  "revokedKeys": [
    { "fingerprint": "SHA256:...", "publicKey": "ssh-ed25519 AAAA...", "admin": "bob", "revoked": "...",
      "revokedBy": "alice", "serial": 2 }
  ]
}
```

Admin uids count up from 20000 and are never reused, so a removed admin's files can't be inherited
by a new one. An invited admin has an `invite` (the hash of the code and when it expires) and no
password or TOTP secret yet.

## The root key and the pepper

On its first start accessd makes the box's **root key** (ed25519) and a 32-byte **pepper**, and
seals both through init's KeyCustody (`root-key`, `access-pepper`): in the TPM when there is one,
otherwise under the key file. Each is used only once its sealed copy reads back. The root key's
private half is held in memory only; its public half is written to
`/var/lib/sneakers/ssh/root_key.pub` for sshd. The root key signs the SSH certificates of the keys
the box issues and makes the root-shell codes; the Access page shows its fingerprint.

## Passwords and TOTP

- **Passwords:** at least 12 characters, no composition rules, paste allowed, no forced expiry
  (NIST SP 800-63B). A password on the breached-password list (`internal/credentials/breached.bin`,
  rebuilt by `scripts/breached-passwords.sh`) or equal to the admin's name is refused
  (`ACCESS_PASSWORD`). The store keeps argon2id (64 MiB, 3 passes, 4 lanes, a 16-byte salt) over
  HMAC-SHA-256(pepper, password).
- **TOTP:** RFC 6238, SHA-1, 6 digits, 30 seconds, one step of drift either way, unique per admin
  and mandatory. The secret is sealed with AES-256-GCM under a key derived from the pepper, bound to
  the admin's name. A step's code is taken once, so a step-up needs a fresh one.

## Lockout and throttling

The same book (`/var/lib/sneakers/access/lockout.json`) covers :8443 sign-in, step-up, the closed
shell's TOTP check, the root-shell code page and wrong root-shell codes:

- 3 consecutive failures within 15 minutes lock the account for 15 minutes (NIST SP 800-53 AC-7),
  or, with the owner's `LOCKOUT_MODE_UNTIL_UNLOCKED`, until an owner unlocks it
  (`AccessService.UnlockAdmin`). A success resets the count. A locked account refuses even the right
  credentials (`ACCESS_LOCKED`).
- 10 failures from one address within 15 minutes, whatever names were tried, hold that address off
  for 15 minutes (`ACCESS_THROTTLED`).
- Every lock (`access.lockout`), throttle (`access.throttle`) and unlock (`access.admin.unlock`) is
  in the OS audit log. Refusals carry a `SignInRefusal` detail: the tries left, or when the lock or
  the throttle ends.

## Issued SSH keys

`AccessService.IssueSshKey` (step-up) makes an ed25519 key pair for the caller and signs an SSH
user certificate for it with the root key: principal the admin's name, valid for the policy's days
(default 365, 1 to 1825), `permit-pty` only, a serial from `nextSerial`. The private key is
returned once and never kept. Admins never bring their own login keys.

## Invariants

Checked on every write. A write that breaks one is refused with its code and nothing changes.

- Admin names match `^[a-z][a-z0-9_-]{1,30}$`, are unique, and aren't a system account: `root`,
  `maint`, `enrol`, `sshd`, `sshkeys`, `nobody`, `osadmin`, `console`, `setup` (`ACCESS_NAME`).
- A key belongs to one admin; no login key equals a recovery key; no two recovery keys are equal
  (`ACCESS_KEY_DUPLICATE`).
- At most three recovery keys (`ACCESS_RECOVERY_KEY_LIMIT`).
- Once the first admin exists: at least one owner who can sign in (`ACCESS_LAST_OWNER`), and a
  roster of admins only, never empty, with a threshold from 2 to N (1 for a roster of one)
  (`ACCESS_QUORUM`).
- Once setup is done: at least one recovery key (`ACCESS_LAST_RECOVERY_KEY`).
- The access settings are within their bounds (`ACCESS_POLICY`).

Writes are serialized, and each one runs on the state the previous one left, so two sessions
demoting the last two owners at once can't both succeed.

## Removed keys are revoked

An issued key that leaves the store, removed on its own or with its admin, by any surface (the page
or the console), goes on `revokedKeys` in the same write, with its certificate serial, with its admin, the time
and who removed it (`revokedBy`: the admin on the page or in the closed shell, or `console`). A key
revoked before the store recorded this has no `revokedBy`, and `ListAdmins` reports it as
`unknown`. While it's there:

- it is on sshd's revocation list, `/var/lib/sneakers/ssh/revoked.krl`, as an explicit key and as a
  serial of the root key's certificates, so sshd refuses it at once.
  The list is written inside the store's write, before the store file is replaced: when the list
  can't be written the change is refused and the key stays, so a key is never out of the store and
  still accepted. accessd writes the list from the store again when it starts;
- a root shell it opened ends, and an open challenge from its login closes.

An owner takes a key off the list with `AccessService.UnrevokeKey` (step-up, audited as
`access.key.unrevoke`); `ListAdmins` returns the revoked keys, each with
`revoked_by`.

## Unix accounts

`/etc` is read-only in the root image, so `/etc/passwd`, `/etc/group` and `/etc/shadow` are symlinks
(`os/rootfs/etc/`) into `/run/sneakers/accounts/`. accessd renders the three files from the store at
start and after every change, each through a tmp file and a rename.

| Account | uid | Shell | Notes |
|---|---|---|---|
| `root` | 0 | `/usr/sbin/nologin` | no login: no keys, no password |
| `sshd` | 100 | `/usr/sbin/nologin` | OpenSSH privilege separation |
| `sshkeys` | 101 | `/usr/sbin/nologin` | unused |
| `osadmin` | 102 | `/usr/sbin/nologin` | the unprivileged :8443 server |
| `nobody` | 65534 | `/usr/sbin/nologin` | |
| each admin | 20000 and up | `/usr/bin/sneakers-shell` | home `/run/sneakers/home/<name>`, empty and root-owned |

No login reaches uid 0: the root shell runs under accessd through the challenge and its code. Every
`/etc/shadow` entry is `*`; admin passwords live only in the access store.

## The :8443 setup page

On first boot :8443 runs from the start and the console shows its address, its certificate
fingerprint and a one-time **setup code**: 16 Crockford base32 characters (`7PQK-NMS9-4XTB-2DWE`;
no I, L, O or U; case, dashes and spaces don't matter; `O` reads as `0`, `I` and `L` as `1`). It
works once, for 60 minutes (then a new one is shown), and only allow-listed sources may try. Five
wrong tries lock it: no code works until the console asks for a new one. accessd alone holds it,
sealed through KeyCustody (`setup-code`) so a restart shows the same code; it is never written to a
plain file or a log, and no :8443 call returns it: only the console's info stream carries it. It is
destroyed once the first admin exists. A browser that redeems it (`SetupService.RedeemCode`) gets a
code session (`__Host-osadmin-code`, with a CSRF token), which ends after 30 minutes without a call
(the console then shows a new code). The console's "this isn't you" (`access.v1
SetupService.ResetSetupCode`) ends it too.

The stepper's six steps (`GetSetup` reports them and the current one; calls out of order are
`SETUP_INCOMPLETE`):

1. **The setup code.**
2. **The first admin:** `CheckPassword` as it is typed, `BeginCredentials` (name and password; a TOTP
   secret comes back, as a QR URI and in base32), `CompleteCredentials` (a code from the new
   authenticator). Only then is the admin stored: an owner and the first root operator. The setup
   code is used up for good, the browser is signed in, and accessd starts sshd.
3. **Recovery keys,** one to three (`ssh-ed25519`, or `ssh-rsa` of 3072 bits or more). Each change asks
   init for a new escrow encrypted to the whole set and writes it to
   `/var/lib/sneakers/backup/escrow/escrow-<time>.age`; when the escrow fails, the keys don't change.
   The newest escrow can be downloaded.
4. **The network** (optional): change it on the Network page, or `AcknowledgeStep`.
5. **The protection** (read only): `AcknowledgeStep`.
6. **Sign in** once with the name, the password and a TOTP code; with one admin the single-admin
   warning is confirmed (`AcknowledgeSingleAdmin`). **Finish** (or the console's `Setup.Complete`)
   checks every step, writes `/var/lib/sneakers/setup/done` and links to the product's own `/setup`.
   Product services list `setup/done` in their `start-when` paths, so none starts before.

**Invitations.** An owner's `AddAdmin` returns a one-time invitation code (24 hours); the new admin
redeems it on :8443 and sets their own password and TOTP secret the same way. `ReinviteAdmin` clears
an admin's credentials, ends their sessions and gives a new code.

**Recover access.** The console's `BeginRecoverAccess` shows a code made and kept the same way as
the setup code (16 characters, 60 minutes, single use, 5 tries, sealed, destroyed on use) for
`https://<address>:8443/recover`: it gives an existing owner a new password and TOTP secret (their
lockout is cleared and their sessions end), or makes a new owner on the roster. Every admin sees a
notice at their next sign-in, and Status warns for 24 hours.

## The :8443 sign-in

`sneakers-osadmin` serves the appliance admin on port 8443 of the management addresses only, and
forwards every call to accessd, which holds the sessions and decides ([accessd](#accessd)).
`SignInService.SignIn` takes the name, the password and a TOTP code; a wrong name, password or code
gets the same answer (`ACCESS_CREDENTIALS`), under the lockout. Each sign-in is audited
(`signin.password`).

### Sessions

| Rule | Value |
|---|---|
| Cookie | `__Host-osadmin-session`: `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, no `Domain` (host-only) |
| CSRF | the session's token in `X-CSRF-Token` on every call that changes something |
| Idle timeout | 15 minutes; every call moves it |
| Absolute limit | 8 hours |
| Per admin | at most 5; a sixth sign-in ends the oldest |
| Storage | memory only, in accessd: a restart of `sneakers-accessd` signs everyone out (a restart of `sneakers-osadmin` doesn't) |

Every call checks the admin still exists and can sign in, so removing or re-inviting an admin ends
their sessions; changing the password ends the admin's other sessions. A role change applies to live
sessions at once.

### Roles, the roster and step-up

| | Can |
|---|---|
| `owner` | everything, including admins, roles, the roster, the access settings, the recovery keys, setup and Secure Boot |
| `admin` | every page and action except managing other admins and the owner-only actions; manages their own password, authenticator and SSH keys |
| root operator (the roster, either role) | opens the root shell; approves a factory reset |

The first admin is an owner and the first root operator; the last owner can't be demoted or removed
(`ACCESS_LAST_OWNER`).

Sensitive actions need a sign-in or a fresh TOTP code (`SignInService.StepUp`) from the last 5
minutes (`ACCESS_STEPUP_REQUIRED`). [osadmin-api.md](osadmin-api.md) lists the role, step-up and
audit action of every method.

## Status, Network, Logs and Power

- **Status:** the version and slots, the protection level and custody mode, the management
  addresses, the state volume's use and daily growth, the :8443 certificate, and the warnings:
  exposure (a public management address with an allow-list open to any source), reduced protection
  (its reason and how to raise it, in the console's words), the self-signed certificate, an
  unsynced clock, and a console Recover access in the last 24 hours.
  The Secure Boot setting is changed here (owner, step-up, the host name typed to confirm).
- **Network:** reads and changes netd's settings. A change is undone unless `ConfirmNetwork` comes
  within 120 seconds from a session that still works.
- **Logs and audit:** the OS audit log, newest first, filtered by action, with its chain state, and the
  whole log as a download.
- **Power:** reboot and shut down, graceful by default; the page lists the live sessions first
  (the :8443 browsers, the SSH logins and the root shells), and an owner can end any of them
  (step-up, audited as `session.end`; see [osadmin-api.md](osadmin-api.md)).
  Init drains the services, audits, syncs and unmounts before it acts ([factory-reset.md](factory-reset.md)).
  A forced reboot or shutdown skips the drain and needs a second, explicit confirmation
  (`POWER_FORCED_CONFIRM` without it); the audit entry records `mode` as `graceful` or `forced`.

## The factory reset quorum

A factory reset from :8443 needs a quorum of root operators, M of N, never one person.

- **The roster** is the root-operator roster, set on the Access page (owner, step-up): N admins and
  the threshold M, from 2 to N (a roster of one opens the root shell but approves no reset). The
  first admin starts it; a store from before that is every admin with two approvals. Members who are later removed drop out and the
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

`sneakers-accessd` is the root service that owns access: the access store, the root key and pepper,
the one-time codes, the :8443 sessions and the lockout, the root shells, the OS audit log, and the
files rendered from the store. It also runs the :8443 API's
backend, so `sneakers-osadmin` runs as the unprivileged `osadmin` user and holds no session, key or
store. Both are in init's service table (`os/rootfs/services.d/`):

| Service | Runs as | Phases | Restart |
|---|---|---|---|
| `accessd` (`/usr/bin/sneakers-accessd`) | root | firstboot, normal | always |
| `osadmin` (`/usr/bin/sneakers-osadmin`) | `osadmin` (uid 102) | firstboot, normal | always, after accessd is ready |
| `sshd` (`/usr/bin/sneakers-sshd-run`) | root | firstboot (accessd starts it once the first admin exists), normal | always |

### access.sock

accessd serves `/run/sneakers/access.sock` (mode 0666; the protos are
`proto/sneakers/appliance/access/v1/access.proto`). Every connection's peer is read with
`SO_PEERCRED`, and the peer uid is the caller's identity, never a field the client sends. Any other
uid is refused before a byte is read.

| Peer | Gets | As |
|---|---|---|
| root | every method of `AccessService`, `NetworkService`, `SetupService` (with `GetConsoleInfo`, the `WatchConsoleInfo` stream, `ResetSetupCode` and the Recover access code) and `ElevationService`, and `LocalService` | the console (an owner named `console`), firstboot, or `sneakers-elevated` |
| an admin uid (a closed-shell login) | `SshLoginService` (the TOTP check, first) and the methods the shell needs: status, admins, keys, network show/set/confirm, the setup recovery key, `BeginRootShell`, `OpenRootShell`, and `LocalService` | that admin, with that admin's role |
| `osadmin` | the :8443 API (`sneakers.appliance.osadmin.v1`), the upload and the audit export, and `BindingService` | the signed-in admin (or the code session) each call carries |

- The console-only methods (`AddRecoveryKey`, `ResetAllowList`, `Complete`, the console info and
  codes, `TerminateElevation`, `BeginElevatedSession`, `EndElevatedSession`) refuse an admin uid
  with `ACCESS_FORBIDDEN`, even an owner's.
- A uid in the admin range with no admin behind it is refused (`ACCESS_FORBIDDEN`).
- A closed-shell login sends the fingerprint of the key sshd says signed it in
  (`Sneakers-Key-Fingerprint`) and its SSH client address (`Sneakers-Source`). A fingerprint that
  isn't one of that admin's keys is refused.
- For `osadmin`, accessd checks the session cookie, the CSRF token, the role and the step-up of
  every call itself; a call with no valid session is `ACCESS_SESSION`. The browser's address comes
  from `Sneakers-Client-Address`, which accessd reads from the `osadmin` uid only.
- Every local call is checked against the same per-method role as on :8443 and written to the OS
  audit log with the `ssh` or `console` surface.

accessd also serves `/run/sneakers/rootshell.sock` (admin uids only) for the root shell
([ssh-and-elevation.md](ssh-and-elevation.md#the-root-shell)).

### What accessd renders

On start and after every change to the store, accessd writes:

- `/run/sneakers/accounts/{passwd,group,shadow}` and the empty homes under `/run/sneakers/home/`;
- `/run/sneakers/ssh/sshd_config`, once an admin can sign in: listening on netd's management
  addresses (link-local ones left out), with only the admins who can sign in allowed. It renders into
  a new directory, has the pinned sshd check it (`sshd -t`), and swaps it in whole; a config sshd
  refuses is never swapped in. When it changed it sends `sneakers-sshd-run` (the pid in
  `/run/sneakers/sshd.pid`) a `SIGHUP`, and sshd-run checks again before it tells sshd. See
  [sneakers-sshd-run](ssh-and-elevation.md#sneakers-sshd-run).

At start it also makes the SSH host keys when they are missing, creates `/var/lib/sneakers/osadmin/`
owned by `osadmin` (the :8443 certificate) and the root-only `/var/lib/sneakers/osadmin-api/` (the
update policy, history and uploads, and the disk samples).

### The update key

The `.bin` decryption key is read from the running UKI on each use, in accessd (root), and never
written to disk. The upgrades design gives it to `sneakers-upgraded`, which isn't on the box yet;
it moves there when that lands.

### When accessd is down

- New SSH logins and :8443 sign-ins are refused: the TOTP check needs accessd.
- An open closed shell's accessd commands say the appliance services are unavailable, and `status`
  shows the last status accessd kept (`/run/sneakers/access/status.json`, refreshed every minute and
  on every status call) with the time it was taken.
- :8443 answers every call with Connect `unavailable` and the same sentence. Status, for a browser
  accessd accepted in the last 8 hours, gets the last status `sneakers-osadmin` saw (or the file),
  with an `accessd` health entry saying it's down.
- Init restarts accessd (`restart: always`).

The root shells also live in accessd; see [ssh-and-elevation.md](ssh-and-elevation.md#the-root-shell).
Every minute accessd expires challenges, codes and tickets whose time is up and ends the record of
a root shell whose `sneakers-elevated` is gone. While accessd is down no root shell can start.

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
