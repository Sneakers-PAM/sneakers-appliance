# Product resources

The Resources page on :8443 shows, and will edit, the settings of the installed product's PostgreSQL
cluster: the replica count, every `postgresql.parameters` entry, PgBouncer's pool sizes and the
storage size. It is `ResourcesService` ([osadmin-api.md](osadmin-api.md)), for admins. The cluster is
the one the product's `data_move` targets ([data-move.md](data-move.md)); a box with no product, or a
product without one, answers `NOT_AVAILABLE`.

> **What is built.** Reading the cluster and checking a change are in. Saving a change is not: the
> box doesn't yet keep an overlay on the cluster's chart values or apply one (Sneakers-PAM/sneakers-appliance#537,
> parts 2 and 3). Until then **the settings in force are read back from the running cluster**: the
> servers connected, the volume's size and the parameters whose value isn't the server's own default.
> PgBouncer's sizes can't be read that way, so `GetResources` says `pools_known` false and they read as 0;
> a preview leaves pool sizes alone while they're unchanged.

## What the page shows

| Card | From |
|---|---|
| Replicas | each server's role (primary or replica), its replication state, whether it is streaming (healthy), and how far its replay is behind what the primary sent, in bytes |
| Storage | the data volume's size (`df` on the data directory; 0 when it can't be read) and what the databases hold |
| PgBouncer pools | the settings in force; see the note above |
| Parameters | every row of `pg_settings`: its value and unit, the server's built-in default, whether a change needs a restart (`context` is `postmaster`), whether one is waiting for a restart, and whether the box checks edits to it |

The box reads the cluster with `psql` in the cluster's first pod, as the data move does, so no password
leaves the pod.

## The rules

`PreviewResources` takes the complete settings wanted, not a patch, and answers each change's before and after.

- **Replicas** are never blocked above 1: more replicas than the cluster has nodes is a warning, since
  the extra ones share a node and add no protection from losing one. 0 is refused, as it would remove the database.
- **Storage** only grows (a volume can't be shrunk in place). The same size is no change.
- **Parameters** may be any: a name is lower-case letters, digits and underscores with at most one dot,
  and a value has no newline, quote or backslash. One the box knows (sizes, times, numbers, booleans,
  a few enums such as `synchronous_commit`) is type-checked; one it doesn't know passes with a warning,
  and PostgreSQL itself refuses a wrong value at start. A change to a parameter PostgreSQL reads only at
  start is marked as needing a restart.
- **PgBouncer** pool sizes are not negative, the default pool and the client limit at least 1; a minimum
  pool above the default is a warning.

A refusal is `RESOURCES_INVALID` and names the setting, as `parameters.work_mem` or `storage`.
