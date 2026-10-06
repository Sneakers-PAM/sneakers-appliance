# Code ported from CryptOS-PKI

Some packages start from CryptOS-PKI's `cryptos-node` (Apache-2.0). Each ported file keeps the line
`Copyright The CryptOS Authors.` under its Sneakers-PAM header, and `NOTICE` names the source. From
the port on, the two copies evolve separately; fixes are carried across by hand when they apply.

| Here | From | Ported at | Changed |
|---|---|---|---|
| `internal/switchroot`, `cmd/sneakers-switchroot` | `internal/switchroot`, `cmd/cryptos-switchroot` | `442b136b0783` | the root is a dm-verity partition found by its root hash (or the install medium's image file), not a SquashFS inside the initrd |
| `internal/tpm` | `internal/tpm` (`tpm.go`, `srk.go`, `seal.go`) | `442b136b0783` | none in substance; the signing-key code isn't ported |
| `internal/luks` | `internal/storage/luks` | `442b136b0783` | `Erase` (luksErase plus a header wipe, used by the reset flow) isn't ported |
| `internal/ukipcr` | `internal/ukipcr` | `442b136b0783` | only `.linux`, `.initrd`, `.cmdline`, `.osrel`, `.uname` and `.sbat` are accepted |
| `build/uki/assemble.sh` | `build/uki/assemble.sh` | `442b136b0783` | the appliance command line and initrd, `.uname` and `.sbat`, and the six-section check |
| `build/kernel/build.sh`, `os/kernel/config-base`, `os/kernel/profiles/vmware.config` | `build/kernel/` | `442b136b0783` | k0s options added, lockdown from the command line, every amd64 profile merged into one kernel, the tag commit checked |
| `build/static/{cryptsetup,e2fsprogs,gptfdisk}.sh` | `build/{cryptsetup,e2fsprogs,gptfdisk}/build.sh` | `442b136b0783` | cryptsetup also builds the static veritysetup |

Never ported: `internal/reset` and every reset verb, `build/uki/sign.sh`, `cmd/cryptos-sbkey`, and
the `nodeid` state-key mode.
