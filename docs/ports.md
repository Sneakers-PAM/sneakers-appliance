# Code ported from CryptOS-PKI

Some packages start from CryptOS-PKI's `cryptos-node` (Apache-2.0). Each ported file keeps the line
`Copyright The CryptOS Authors.` under its Sneakers-PAM header, and `NOTICE` names the source. From
the port on, the two copies evolve separately; fixes are carried across by hand when they apply.

| Here | From | Ported at | Changed |
|---|---|---|---|
| `internal/switchroot`, `cmd/sneakers-switchroot` | `internal/switchroot`, `cmd/cryptos-switchroot` | `442b136b0783` | the root is a dm-verity partition found by its root hash (or the install medium's image file), not a SquashFS inside the initrd |

Never ported: `internal/reset` and every reset verb, `build/uki/sign.sh`, `cmd/cryptos-sbkey`, and
the `nodeid` state-key mode.
