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
