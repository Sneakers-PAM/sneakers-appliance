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
  signal doesn't say so), or on a box that was imported before (a re-import). On a box whose
  product is already set up, an owner gets back to an empty product with `sneakers reset` over
  SSH, which needs no quorum, so a single-admin box can import too
  ([upgrades.md](upgrades.md#removing-the-product)); Apply on the Product card then installs it
  again, and the import opens before its setup.
- **Upload** (`POST /import/upload?kind=...`, `import.upload`): the export bundle, the mapping file,
  a proposal sheet and its type rules, each under a fixed name in the import directory. A new
  upload replaces the earlier file of its kind.
- **Steps** (`ImportService.RunImportStep`, step-up, `import.run`): `review`, `convert` (a proposal
  sheet into the mapping file), `check` (the mapping file against the bundle), `import` (with
  rehearsal, re-import and the first admin's email) and `verify`. The box fills the bundle's Job
  template with the step's `sneakers-migrate` arguments and the import directory, and writes it into
  the import stack, which k0s applies. One step runs at a time. Each step writes what it prints,
  and its exit code, into `out/` (`MIGRATE_OUTPUT_FILE`), and the page shows them with the step's
  report and, for a review, the mapping template to download. The output is shown as plain text:
  the terminal colour codes of the step's console log are dropped when the box reads it.
  A step that ends without writing its exit code is read from its Job. That covers a step the
  kernel killed for its memory and one that failed before it wrote anything. The box reads the
  step's Job and pods with the installed k0s. Any of these ends the step as failed, with its exit
  code and a reason the page shows: a container that terminated (`OOMKilled` is exit code 137),
  a pod that failed (evicted, say), or a Job marked Failed. An example reason is "the review step
  ran out of memory (limit 4Gi)". The box keeps that end next to the step's output
  (`out/<job>.ended.json`), so the step still shows how it ended after its Job is gone, and the
  next step can start. A step whose Job k0s hasn't applied yet, or whose pod still runs, shows
  running. Before a step starts, the box checks that it fits in memory ([Memory](#memory)).
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
  export, the import key and the outputs. Reports worth keeping are downloaded first. A step never
  holds the close: a step that failed or ran out of memory has ended (above), and a step still
  running is stopped. The box deletes its Job and its pod first, and the page asks before it
  closes ("this stops the running step"). With the switch off the held phases come back, and the
  box leaves maintenance.

The migrate caller the vault and audit admit, and the NetworkPolicies that let the migrate
component reach them, PostgreSQL and the Kratos admin API, are in the product's main stack. With
the import closed there is no `sneakers-migrate` service account, so nothing can run as that caller.

While an import is open a phased product is held after the phase `import.after` names
(`services` for Sneakers, [upgrades.md](upgrades.md#the-phases)): PostgreSQL, Kratos, the identity
service, the vault and the audit service, which the import writes to, run; the gateway and the web
apps (sign-in, the MCP) are scaled to 0, and the box state is `maintenance`, so 443 says the box is
in maintenance and nobody signs in or writes while the import runs. A reboot with the import open
comes back to the same hold. Verify counts the hold as ready. Closing the import brings the held
phases back, and the box says running once they're Ready.

There is no rollback: if an import is wrong, fix the cause and import again with **Re-import**
(`--wipe-target`), which empties the product's data first. On an imported box it replaces the
earlier import; a box whose data didn't come from an import is refused.

## Memory

`sneakers-migrate` holds the whole bundle in memory while a step runs, about 2.3 KB for each
audit record, so a step's memory grows with the source's audit chain. The table has the peaks
measured on the real bundle (the real-bundle job's [import leg](testing.md#the-real-bundle-job))
with a 727,000-record chain, a 37 MB bundle:

| Step | Peak memory |
|---|---|
| export (on the source, not the box) | 1.6 GiB |
| review | 1.5 GiB |
| convert | 1.8 GiB |
| check | 1.1 GiB |
| import | 2.0 GiB |

Each step's Job (`build/product/sneakers/import-job.yaml`) requests 1Gi and is limited to 4Gi,
about twice the largest peak, which leaves room for a chain of about 1.4 million records. A step
that goes past its limit is killed by the kernel and ends as failed with that reason (above).

**What the box needs.** With the product running on the same box, the box and the product use
1.3 GiB. With the import open, and the gateway and the web apps held, they use 1.27 GiB. A step
adds up to its 4 GiB limit, so an import needs about 5.3 GiB. A 16 GiB box (4 vCPUs, the
production size) keeps about 10.7 GiB free while the largest step runs. An 8 GiB box keeps about
2.7 GiB free.

**A step that can't fit isn't started.** Before a step starts, the box compares the step's memory
limit with its available memory (`MemAvailable`). If the limit is larger, it refuses with
`NOT_AVAILABLE`, for example: "the review step may use up to 4Gi of memory, and the box has
2.0 GiB available; an import needs a box with that much free". A box that can't read its memory
starts the step.

The import's verify asks the audit service to verify the whole chain. The service reads the chain
in batches and checks it as it reads, so its memory stays flat however long the chain is.

## The key ceremony on an imported box

The appliance's own setup (the setup code, the first appliance admin, the recovery keys, the
network and protection) is done by hand as usual, before the import; only the product's own
first-run setup is skipped. Keep the recovery keys and the escrow file as the setup page says: on
disk to start, then in the new Sneakers and offline. On disk is a starting point, not the resting
place.
