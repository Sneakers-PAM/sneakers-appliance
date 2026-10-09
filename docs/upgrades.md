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

## The steps of an update

osadmin keeps the last stage, apply or revert as its steps, in
`/var/lib/sneakers/osadmin-api/upgrade-progress.json`, and serves them add-only as
`upgrade_progress` on `GetUpgrades` and `GetStatus` (and, reduced to the steps' ids, labels and
states, on the public `GetPhase`, for the restart page). The console's maintenance screen
([console.md](console.md#the-status-screen)), Updates and the restart page on :8443 all show the same
list. A base update has six steps:

| id | Label | What it covers |
|---|---|---|
| `verify` | Verifying (signature, channel, SHA-256) | reading the `.bin`'s header, its signature, its channel and its payload's hash, and that it fits the running base |
| `stage` | Staging into slot B (the slot the box isn't running from) | decrypting and unpacking the release, then init writing its root image into the slot, with `done_bytes` of `total_bytes` written (init's `Image.Status` reports `stage_written_bytes` of `stage_total_bytes` while it writes), the sealed key copy and the ESP entry |
| `switch` | Switching slots | `Image.Activate` (an apply) or `Image.Rollback` (a revert) |
| `reboot` | Rebooting | the reboot; it stays the current step until the booted release takes over |
| `health` | Checking health | the booted release's MarkGood loop waiting for setup, init and netd (the detail says which) |
| `mark_good` | Marking good | `Image.MarkGood`; a refusal is the detail, and the loop tries again each minute |

A stage runs the first two and leaves the rest pending for Apply, which carries the same record
on; an apply of a release staged before this record starts with those two done. A revert has no
file, so it starts at `switch`, and its version is the release it goes back to. A product bundle
has `verify`, `stage` (into the free product slot), `switch` and `restart` (restarting the product),
and no reboot. Until a stage has read the file's header it doesn't know which of the two it is, so
its record starts with `verify` alone and no target; the base or product steps replace it once the
header is read, so a product stage never shows the base's slot, reboot or health steps.

### The product coming up

Restarting the product only starts k0s; the product takes minutes more to answer. So a product
apply or revert goes on past `restart` with five more steps, and stays `in_progress` until the
product answers on 443. Updates, the restart page and the console's maintenance screen show them
like the others:

| Step | Label | Done when |
|---|---|---|
| `k0s` | Starting k0s | the Kubernetes API answers (`/readyz`) |
| `images` | Importing the images | containerd lists every image in the bundle's `images/` (the detail counts them) |
| `manifests` | Applying the product's stacks | every stack in the bundle's `manifests/` has an object labelled `k0s.k0sproject.io/stack` (the detail names those still missing) |
| `pods` | Waiting for the pods to be ready | every pod that should run is Ready; a finished Job's pod doesn't count (the detail counts them) |
| `edge` | Opening the product on 443 | `https://127.0.0.1:443/` answers without `Sneakers-Box-State` and not with 502 to 504: the product, not edgefall's page or an edge error |

accessd (root) asks the installed bundle's own k0s (`k0s kubectl` with
`/var/lib/k0s/pki/admin.conf`, `k0s ctr` on `/run/k0s/containerd.sock`) every 3 seconds
(`internal/productup`); the apply has answered by then, and the record follows on its own. An
edge that answers with the product ends it, whatever the earlier checks say. A step can go back (a
pod falls over), and the step after it is pending again. A check that fails leaves the step where
it was. When the product hasn't come up 20 minutes (`ProductUpBound`) after following began, the
step it's on fails with `UPGRADE_PRODUCT_START`; the root shell's `kubectl` shows what holds it.
When accessd restarts in the middle, it picks the record up again at start rather than failing it.
Downloading from the mirror comes before all of this, as `receiving` and `held_upload` on
`GetUpgrades`; unpacking is the `stage` step.

Each step is pending, active, done or failed, and `in_progress` is set while one is active. A
failed step carries why in its detail and the failure's code (`UPGRADE_SIGNATURE`, say) in the
record's `code`; the steps after it stay pending. A release the box doesn't come up on fails at
`health`, naming both releases ("0.2.0 didn't come up healthy, so the box went back to 0.1.0 by
itself."): the fallback is boot counting's, unchanged. A step osadmin runs in one call (verifying,
staging, restarting the product) that's found active when osadmin starts was cut off by a restart,
and fails as such; the product's coming-up steps aren't, they're followed again. A reboot that never comes (init took the request but the box didn't go down)
fails at `reboot` with `UPGRADE_NO_REBOOT` once 10 minutes (`RebootBound`) have passed on the boot
the step started on: accessd checks each minute, comparing the kernel's boot ID with the one the
step recorded, so osadmin restarting on the same boot isn't mistaken for the reboot. Maintenance
ends, Apply is offered again, and the failure gets an `upgrade.reboot-missed` entry in the OS audit
log (actor `osadmin`, the version and how long it waited) and a failed line in the update history.
The boot entry the switch made is left as it is, so the next restart still boots that release. A
reboot init refuses fails the step at once with init's reason. The next stage, apply or revert
replaces the record.

## Updating from :8443

The Updates page drives the same flow for an uploaded or a fetched `.bin`:

1. **Get the file.** Upload it (`POST /upload`, any admin) or fetch it (`UpgradeService.FetchUpdate`,
   the file name such as `sneakers-appliance-0.2.0-amd64.bin`) from the configured mirror, then,
   when the policy's `direct` is on, from the release source (the GitHub Release of the version the
   name carries; production builds only). With no mirror and `direct` off the box is air-gapped: it
   never makes a network fetch (`UPGRADE_AIR_GAPPED`) and upload is the only path. The mirror is an
   `http://` or `https://` URL ([an internal mirror](#an-internal-mirror)); the environment's proxy
   applies.
2. **Stage** (owner, no code: it only writes the inactive slot, and nothing runs until Apply). The signature, the channel and the payload's SHA-256 are verified
   before anything is decrypted or unpacked; a patch must name the running version as a base.
   While the call runs, Updates asks `GetUpgrades` each second and shows the steps, with the bytes
   written into the slot.
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
   again and sends the owner to sign in. The restart page lists the steps from the public
   `GetPhase`: rebooting while the box is down, then checking health and marking good once :8443
   answers, and it sends the owner to sign in when they're done, or shows the failed step. Both are
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

**One file at a time, and Cancel.** The box holds one file at a time. While an upload or a fetch is
coming in (`GetUpgrades.receiving`), a file is held (received or fetched, not yet staged or
discarded: `GetUpgrades.held_upload`, with its id, the name the browser sent in `X-File-Name` or the
fetched file's, its size, when it came and from where), or a stage runs, a new upload answers `409`
and a fetch is refused, both with `UPGRADE_BUSY`. A transfer the browser aborts removes its partial
file, and a partial file a crash left is removed before the next one comes in.
`UpgradeService.DiscardUpdate` (owner, no code, audited as `upgrade.discard`, with a `discard` line
in the history) drops a held file by its id, with its partial `.tmp`, unpacked layout and details
(`UPGRADE_UPLOAD` when there's no such upload), or, with no id, unstages the staged release of its
`target`: for the base, init's `Image.Unstage` removes the release's ESP entry (so it never boots)
and its sealed copy of the state key, and the slot is left for the next stage to overwrite; for the
product, the `staged` link and its slot's files go, and the installed and previous slots stay.
Nothing is dropped while a stage runs (`UPGRADE_BUSY`), and with nothing staged it's
`UPGRADE_NOT_STAGED`. A base stage removes the previous release to make room (above), so after
unstaging one there's no previous release to revert to until the next apply.

## An internal mirror

An air-gapped site can serve the release files from a web server of its own and set it as the
policy's mirror (the design is in [update-mirror.md](update-mirror.md)).

- **What it serves:** the `.bin` files and the index side by side under one base URL,
  the names exactly as released: `<base>/sneakers-appliance-<version>-<arch>.bin`,
  `<base>/sneakers-product-<version>-<arch>.bin` and `<base>/sneakers-product-index.json`. Any
  static web server will do.
- **`http://` or `https://`.** The URL has a host and no user name, password or query. Over plain
  HTTP the box's only protection is the signature check, which every `.bin` gets anyway before
  anything is decrypted or unpacked: a changed file is refused (`UPGRADE_SIGNATURE`) and deleted.
  Updates says "plain HTTP: integrity from the signature only".
- **A private CA.** An `https://` mirror with a public certificate needs nothing more. For an
  internal CA, an owner adds it on Certificates under Update trust (`TlsService.SetUpdateTrust`,
  one or more PEM CA certificates), optionally with the SHA-256 fingerprint of the mirror's server
  certificate as a pin (`openssl x509 -in server.pem -noout -fingerprint -sha256` gives it; any
  case, colons or not). The CA is added to the system roots for the mirror's fetches only, never
  for the release source, :8443 or the product. There's no way to turn verification off: an
  untrusted certificate is refused (`UPGRADE_MIRROR_UNTRUSTED`) and so is a pin that doesn't match
  (`UPGRADE_MIRROR_PIN`), both naming the presented certificate's fingerprint and issuer.
  `ClearUpdateTrust` removes the trust.
- **Status:** `GetUpgrades.mirror_status` shows the scheme and the last mirror fetch: its result,
  and for HTTPS the server certificate's subject, issuer, expiry, fingerprint and whether the pin
  matched. It's in memory: after a restart it's empty until the next fetch.
- **Base updates from the index:** the index (`sneakers-artifact product-index`,
  [release.md](release.md#the-product-bundle)) has a `base` section next to `products`.
  `ListBaseVersions` reads it from the mirror, then the release source when `direct` allows, and
  offers the base releases this box may stage: full or patch for its architecture and channel,
  stable versions on a production box (every lab build on a lab box), newer than the running base,
  and a patch only for the base it names. A release outside the installed product's base range is
  still listed, marked `outside_product_range` with the range, since staging it needs the owner's
  override. The index is a menu only and isn't signed: the chosen `.bin` is fetched by name
  (`FetchUpdate`) and verified at stage like an uploaded one. An index without a `base` section
  offers no base update.
- **Logging:** every fetch attempt, from the mirror or the release source, is logged with its URL,
  result and duration and audited as `upgrade.source.fetch`.

## The product bundle

The product (k0s, its images and the product's stacks) isn't in the base image. It ships as its own
signed, encrypted `.bin`, `sneakers-product-<version>-<arch>.bin` ([release.md](release.md#the-product-bundle)),
and goes through the same Updates flow as a base update, with the same checks, roles, codes,
audit, history, update window and maintenance gate. What differs is the slots and what an apply
does:

| | Base update | Product bundle |
|---|---|---|
| Slots | the two root partitions and the ESP entries | `/var/lib/sneakers/product/a` and `b` on the state volume, with the links `current`, `staged` and `previous` |
| Stage | `Image.Stage` writes the inactive root, unless the installed product's base range doesn't include it (below) | the bundle must fit the running base, inside its `min_base` to `max_base` range (`UPGRADE_PRODUCT_BASE`, refused before it's decrypted, naming the range and the running base) and be newer than the installed product (`UPGRADE_DOWNGRADE`); it's unpacked into the slot `current` doesn't name, checked (k0s, the images and their signatures against its `release.yaml`, `KIT_BUNDLE_MISMATCH` or `KIT_IMAGE_UNSIGNED`), and only then linked as `staged`; the upload is removed |
| Apply | activates the release and reboots | `ApplyUpdate` with `target: UPDATE_TARGET_PRODUCT` moves `current` to the staged slot (the old one becomes `previous`), restarts k0s through init's Services API and opens 80 and 443 on the service interface; no reboot |
| Revert | `Image.Rollback` and a reboot | `RevertUpdate` with `target: UPDATE_TARGET_PRODUCT` moves `current` back to `previous` and restarts k0s (`UPGRADE_NO_PREVIOUS` when there is none) |

**The base range.** A product bundle names the base versions it fits as `min_base` and an optional
`max_base` ([release.md](release.md#the-product-bundle)). Staging one checks the running base against
it, and `ListProductVersions` offers only those whose range includes the running base. A base update
checks the installed product the other way: a base release outside the installed product's range is
refused at stage (`UPGRADE_PRODUCT_BASE`, naming the product, its range and the release) and the
upload is kept; `StageUpdate` with `override_product_range` stages it anyway, audited with
`override: product-range`, for an owner who installs a product that fits next. A bundle sealed
before the range existed names exact `bases` only: it still installs on one of them, the installed
one isn't checked against a base update, and osadmin's log notes both.

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
staged and previous versions, whether k0s is running, and `name`, the installed product's name for
people ("Sneakers", from the current slot's `<name>-product` header name; empty with no product).
The :8443 nav shows the product's own section under that name, and only while it is set; the closed
shell's product group follows the same header ([ssh-and-elevation.md](ssh-and-elevation.md#product-commands)).
`GetStatus.product` carries the same slots, for the console's Product line
([console.md](console.md#the-status-screen)).

**The policy** (owner, no code): `automatic` applies a staged release once inside the daily window
(default 02:00 local for 2 hours, 45 to 720 minutes), `manual` only when an owner applies it. The
window applies a staged product bundle first, then a staged base release. `direct` (off by
default) lets the box fetch from the release source when no mirror is set or the mirror fails. It's
kept in `/var/lib/sneakers/osadmin-api/upgrade-policy.json`. **The history** of every fetch, stage, apply
and revert, with its outcome and code, is in `/var/lib/sneakers/osadmin-api/upgrade-history.jsonl` and
on the page, newest first.
