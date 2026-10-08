# Image slots and boot counting

A release reaches the box as one signed and encrypted update package, the `.bin`, downloaded from
the GitHub Release or uploaded by hand ([release.md](release.md)). The box verifies the signature
and the channel before it decrypts anything, with the update key read from the UKI it booted; a lab package never installs on a production box.

A box holds at most two releases: the one it runs and one more (the next, or the previous).

**Retention: keep N, drop the oldest.** `Stager.Keep` sets N: the default is 2 and so is the
maximum (`MaxKeep`), because the boot disk has two root partitions, one release in each. A stage
keeps the running release and the newest N-2 others, good entries before bad ones, and removes the
rest with everything tied only to them: the boot entry, the sealed state-key copy (pruned at the
next `MarkGood`), the fetched copy in `/var/lib/sneakers/image-stage/`, and the uploaded `.bin` and
its unpacked layout. A `.tmp` file left by a cut-off ESP write goes as well, so neither the ESP nor
the state volume grows from one update to the next. The root partition itself is simply written
over. There are no pre-update backups: the A/B slots are the way back. The slot count and the
partition layout of an image built from a template are a per-app design choice, made later.

The removal happens at Stage, not Apply, because staging writes over the inactive slot. So
`Image.Status` and `GetUpgrades` name the releases the next stage removes (`next_stage_removes`),
and the Updates page shows "This removes <version> and its files" by the Stage step and in its
confirm dialog.

- `Image.Stage` fetches a release, runs the whole verification chain against the keys compiled
  into the running init, and refuses anything not newer than the running release
  (`UPGRADE_DOWNGRADE`). Nothing is written before that passes. It then writes the root image into
  the slot the box isn't running from (setting that slot's PARTUUID from the root hash), adds a
  sealed copy of the state key for the new UKI (PCR 7 as it is now and the predicted PCR 11), and
  only then writes the ESP entry `EFI/Linux/sneakers-<version>+3-0.efi`. The entries retention
  drops (with N of 2, every one but the running release's) are removed first, and the answer
  names them (`removed_versions`).
- systemd-boot boots the newest entry; each attempt moves one try from left to done
  (`+2-1`, `+1-2`, ...). An entry with no tries left is bad and sorts last, so after three failed
  boots the box falls back to the previous release, and `Image.Status` reports the failed version.
- `Image.Activate` checks a release is staged (`UPGRADE_NOT_STAGED` otherwise); its entry already
  has boot tries, so the reboot that follows boots it.
- `Image.MarkGood`, after the health checks, renames the running entry to `sneakers-<version>.efi`
  and prunes the sealed copies for UKIs no longer on the ESP (the copy made at install time, which
  names no UKI, is kept). accessd calls it when it starts and then each minute until it succeeds,
  once setup is done and init and netd answer; until platformd's health gate exists, those are the
  health checks. It waits while an apply or a revert is under way, so it can't undo a revert before
  its reboot. A release that never gets there (the box doesn't come up on it) uses up its tries.
- `Image.Rollback` marks the running release bad (`+0-n`), so the next boot is the previous one.
  With no previous release it's `UPGRADE_NO_PREVIOUS`. It first writes `loader/sneakers-reverted.json`
  on the ESP (the release, the admin who asked and when), so after the reboot `Image.Status`
  reports `reverted_version`, `reverted_by` and `reverted_at` instead of `failed_version`: a revert
  someone asked for isn't a failed boot. `failed_version` is only for a release boot counting fell
  back from. The next `Image.Stage` removes the record. Status and Updates on :8443 and the console
  show "Reverted from <version> (by <admin>, <time>)" in a neutral tone; "Failed" stays for a real
  fallback.
- `Image.Status` also names the revert target: `previous_version` is the older, good entry still
  on the ESP that `Image.Rollback` would boot. After an update and its `MarkGood` it's the release
  updated from; it's empty on a fresh install, while a newer release is staged (staging removes
  it) and after a revert. osadmin's `GetStatus` and `GetUpgrades` pass it on with `previous_slot`,
  the slot it's in (the one the box isn't running from, `A` or `B`), so Status, the diagnostics
  and Updates read "Other slot: <version> (revert target)", "staged <version>" when one is
  staged, and "empty" only when there's neither.
- With Secure Boot off (TPM mode), the new release's PCR 4 must be predicted from the firmware's
  event log; until that replay is in, staging is refused (`UPGRADE_UNPREDICTABLE`) rather than
  sealed to a guess.

## Updating from :8443

The Updates page drives the same flow for an uploaded or a fetched `.bin`:

1. **Get the file.** Upload it (`POST /upload`, any admin) or fetch it (`UpgradeService.FetchUpdate`,
   the file name such as `sneakers-appliance-0.2.0-amd64.bin`) from the configured mirror, then,
   when the policy's `direct` is on, from the release source (the GitHub Release of the version the
   name carries; production builds only). With no mirror and `direct` off the box is air-gapped: it
   never makes a network fetch (`UPGRADE_AIR_GAPPED`) and upload is the only path. The mirror is an
   `https://` URL; the environment's proxy applies.
2. **Stage** (owner, step-up). The signature, the channel and the payload's SHA-256 are verified
   before anything is decrypted or unpacked; a patch must name the running version as a base.
   A refused file (`UPGRADE_SIGNATURE`, `UPGRADE_CHANNEL`, `UPGRADE_FORMAT`,
   `UPGRADE_PATCH_BASE`) is deleted, never unpacked, and the refusal is audited. Only then is the
   update key read from the booted UKI (by accessd, as root; [access.md](access.md#the-update-key)), the payload decrypted and unpacked, and the layout handed to
   `Image.Stage`. Once it's staged, the upload's `.bin` and its unpacked layout are removed, and
   each older release init removed gets an `upgrade.remove` entry in the OS audit log (the admin,
   the version and the release it made room for) and a `remove` line in the update history; the
   stage's own entry lists them under `removed`. The answer names the slot a base release went into (`slot`, `A` or `B`, from
   init's `SNEAKERS_ROOT_SOURCE`), so the page can say "Staged into slot B".
3. **Apply** (owner) activates the staged release and reboots into it (`UPGRADE_NOT_STAGED`
   when nothing is staged). **Revert** rolls back to the previous release and reboots. Neither
   rides on the step-up window: each request carries its own `totp_code`, a fresh code from the
   owner's authenticator, checked on every call under the sign-in lockout (`ACCESS_CONFIRM` when
   it's empty, `ACCESS_CREDENTIALS` when it's wrong or used already). The page asks for it in the
   same dialog as the typed version, then shows a restart page that waits for :8443 to answer
   again and sends the owner to sign in. Both are
   refused while an elevated shell is open (`UPGRADE_ELEVATED`, naming it), and both put the box in
   maintenance first, which refuses new elevated shells (`ELEV_MAINTENANCE`) until the reboot, or
   at once again if the apply fails ([ssh-and-elevation.md](ssh-and-elevation.md)).
   `GetUpgrades.active_elevations` lists the open elevated shells, so the page shows who holds one
   before an owner tries.

**The elevation override.** An owner may end the open shell and go ahead in the same request:
Apply and Revert take an `elevation_override` with the session's id, a typed confirmation of its
admin and id (`bob E-7KQ2`) and a reason. The override is owner only and needs the same fresh
code as Apply and Revert themselves. A wrong confirmation or an empty reason is refused (`ACCESS_CONFIRM`) and
the shell is left alone; an override naming one session doesn't cover another, which still refuses
with `UPGRADE_ELEVATED`. When it checks out, the session is terminated (an `elevation.terminate`
entry in the OS audit log with the reason, the admin it belonged to and `for: upgrade.apply` or
`upgrade.revert`), and the apply or revert waits, at most 30 seconds, until `sneakers-elevated`
reports the end; a session that hasn't ended by then refuses with `UPGRADE_ELEVATED` and nothing
is applied. The apply's own audit entry and history line name the session it ended. Without an
override the refusal stays. The update window never overrides.

## The product bundle

The product (k0s, its images and the product's stacks) isn't in the base image. It ships as its own
signed, encrypted `.bin`, `sneakers-product-<version>-<arch>.bin` ([release.md](release.md#the-product-bundle)),
and goes through the same Updates flow as a base update, with the same checks, roles, step-up,
audit, history, update window and maintenance gate. What differs is the slots and what an apply
does:

| | Base update | Product bundle |
|---|---|---|
| Slots | the two root partitions and the ESP entries | `/var/lib/sneakers/product/a` and `b` on the state volume, with the links `current`, `staged` and `previous` |
| Stage | `Image.Stage` writes the inactive root | the bundle must fit the running base (`UPGRADE_PRODUCT_BASE`, refused before it's decrypted) and be newer than the installed product (`UPGRADE_DOWNGRADE`); it's unpacked into the slot `current` doesn't name, checked (k0s, the images and their signatures against its `release.yaml`, `KIT_BUNDLE_MISMATCH` or `KIT_IMAGE_UNSIGNED`), and only then linked as `staged`; the upload is removed |
| Apply | activates the release and reboots | `ApplyUpdate` with `target: UPDATE_TARGET_PRODUCT` moves `current` to the staged slot (the old one becomes `previous`), restarts k0s through init's Services API and opens 80 and 443 on the service interface; no reboot |
| Revert | `Image.Rollback` and a reboot | `RevertUpdate` with `target: UPDATE_TARGET_PRODUCT` moves `current` back to `previous` and restarts k0s (`UPGRADE_NO_PREVIOUS` when there is none) |

**The first install** is the same flow with no previous slot. After setup the Updates page lists
the versions to choose from (`ListProductVersions`): the index `sneakers-product-index.json` from
the mirror, then the release source's latest release, filtered to the box's architecture and
channel, the running base, stable versions (no pre-release part; on a lab box every lab build
counts) and, after the first install, versions newer than the installed one, newest first. The
index is only a menu: nothing in it is trusted, and the chosen bundle is verified when it's staged.
On an air-gapped box the admin uploads the bundle instead.

**Nothing starts without it.** k0s's service entry waits for `setup/done` (the first admin exists)
and for an installed bundle (`start-when`, [init.md](init.md#the-service-table)), so a box with no
product bundle runs no k0s and opens no product port. `GetUpgrades.product` shows the installed,
staged and previous versions and whether k0s is running.

**The policy** (owner, step-up): `automatic` applies a staged release once inside the daily window
(default 02:00 local for 2 hours, 45 to 720 minutes), `manual` only when an owner applies it. The
window applies a staged product bundle first, then a staged base release. `direct` (off by
default) lets the box fetch from the release source when no mirror is set or the mirror fails. It's
kept in `/var/lib/sneakers/osadmin-api/upgrade-policy.json`. **The history** of every fetch, stage, apply
and revert, with its outcome and code, is in `/var/lib/sneakers/osadmin-api/upgrade-history.jsonl` and
on the page, newest first.
