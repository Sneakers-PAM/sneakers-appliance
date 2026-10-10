# The Import page

The Import page on :8443 brings an export of an earlier install into the installed product before
its own first-run setup: the users, groups, secrets, folders and audit chain come from the export,
and the box goes into **imported-users mode**. It is the appliance side of
`sneakers-migrate` (sneakers-release `docs/migrate-appliance.md` has the whole move, step by step).

The product declares it in `product.yaml` ([release.md](release.md#productyaml)): a switch whose
stack holds the migrate service account, the Job template the steps run from, the Job's user, the
one-time setup value its own setup consumes, and what to restart after an import.

## How it works

- **Open** (`ImportService.OpenImport`, step-up, `import.open`): turns the import switch on, so k0s
  applies the import stack, and makes the **import key** on the box (an age X25519 identity) in the
  import directory, `/var/lib/sneakers/import`, owned by the Job's user. The page shows its
  recipient: the export is encrypted to it, and the key never leaves the box. An import opens only
  while the product's own setup isn't done (its setup value isn't consumed, and the product's
  signal doesn't say so), or on a box that was imported before (a re-import).
- **Upload** (`POST /import/upload?kind=...`, `import.upload`): the export bundle, the mapping file,
  a proposal sheet and its type rules, each under a fixed name in the import directory. A new
  upload replaces the earlier file of its kind.
- **Steps** (`ImportService.RunImportStep`, step-up, `import.run`): `review`, `convert` (a proposal
  sheet into the mapping file), `check` (the mapping file against the bundle), `import` (with
  rehearsal, re-import and the first admin's email) and `verify`. The box fills the bundle's Job
  template with the step's `sneakers-migrate` arguments and the import directory, and writes it into
  the import stack, which k0s applies. One step runs at a time. Each step writes what it prints,
  and its exit code, into `out/` (`MIGRATE_OUTPUT_FILE`), and the page shows them with the step's
  report and, for a review, the mapping template to download.
- **After an import passes**, the box records it (`/var/lib/sneakers/platform/imported.json`: the
  bundle, the step and the mode; audited as `import.done`) and restarts what the product names (the
  vault, which loads the imported state on start). That is imported-users mode: the product's setup
  value counts as consumed, so the product's own first-run setup is never offered. `verify` waits
  for the restart: until the product is ready again (every workload rolled out and its health check
  answering, as after an update: [upgrades.md](upgrades.md#when-the-product-is-ready)), it's refused
  with `PRODUCT_NOT_READY`, naming what it waits for; try it again once it's ready.
- **The first admin's password** (`ImportService.TakeOwnerPassword`, step-up,
  `import.owner-password`): an import with the first admin's email makes a one-time password, which
  the Job writes to its own file (`MIGRATE_OWNER_PASSWORD_FILE`), never to the output. The page
  shows it once and the box removes the file as it reads it. Every other user sets a new password
  with "Forgot password" and enrols a second factor at first sign-in.
- **Close** (`ImportService.CloseImport`, step-up, `import.close`): turns the switch off, so k0s
  removes the migrate service account and the step Jobs, and removes the import directory: the
  export, the import key and the outputs. Reports worth keeping are downloaded first.

The migrate caller the vault and audit admit, and the NetworkPolicies that let the migrate
component reach them, PostgreSQL and the Kratos admin API, are in the product's main stack. With
the import closed there is no `sneakers-migrate` service account, so nothing can run as that caller.

There is no rollback: if an import is wrong, fix the cause and import again with **Re-import**
(`--wipe-target`), which empties the product's data first. On an imported box it replaces the
earlier import; a box whose data didn't come from an import is refused.

## The key ceremony on an imported box

The appliance's own setup (the setup code, the first appliance admin, the recovery keys, the
network and protection) is done by hand as usual, before the import; only the product's own
first-run setup is skipped. Keep the recovery keys and the escrow file as the setup page says: on
disk to start, then in the new Sneakers and offline. On disk is a starting point, not the resting
place.
