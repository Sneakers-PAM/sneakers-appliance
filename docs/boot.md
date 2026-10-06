# Boot

```
UEFI firmware -> EFI/BOOT/BOOTX64.EFI (systemd-boot, org-signed)
  -> EFI/Linux/sneakers-<version>[+<left>-<done>].efi (the UKI, org-signed)
     -> initrd /init = sneakers-switchroot
        -> /sbin/init = sneakers-init
```

## sneakers-switchroot

The UKI's initrd holds `sneakers-switchroot` and a static `veritysetup`. It:

1. mounts `/dev`, `/proc` and `/sys` and reads the command line (`sneakers.roothash`,
   `sneakers.hashoffset`, `sneakers.version`), which only the signed UKI carries;
2. reads every disk's GPT and picks the root slot (`sneakers-root-a` or `-b`) whose PARTUUID is the
   first 128 bits of the root hash. One UKI finds its root in either slot this way. With no matching
   slot and an ISO 9660 volume labelled `SNEAKERS_INSTALL`, it uses `root-<version>.img` on that
   medium through a loop device (install mode). Otherwise it stops with `ROOT_NOT_FOUND`;
3. runs `veritysetup open ... --hash-offset=<offset> --panic-on-corruption` with the signed root
   hash, so any changed block of the root panics the kernel;
4. mounts the verity device read-only at `/sysroot`, moves `/dev` into it and switch_roots into
   `/sbin/init`.

Any failure panics PID 1; the kernel reboots after `panic=10`, and boot counting falls back to the
previous release.

## The UKI

`build/uki/assemble.sh` builds the unsigned UKI with ukify (systemd-stub), reproducibly from
`SOURCE_DATE_EPOCH`:

| Section | Contents |
|---|---|
| `.linux` | the kernel |
| `.initrd` | `sneakers-switchroot` as `/init` and a static `veritysetup`; no root filesystem |
| `.cmdline` | `sneakers.roothash=<hex> sneakers.hashoffset=<bytes> sneakers.version=<ver> quiet console=tty0 console=ttyS0 panic=10 lockdown=integrity` |
| `.osrel`, `.uname` | the release's os-release and kernel release |
| `.sbat` | the shim line and `sneakers-pam,1`, so a bad release can be revoked by generation |

It then refuses the image unless it carries exactly those six payload sections: `internal/ukipcr`
(ported from CryptOS-PKI) predicts PCR 11 only for them, and a box that can't predict PCR 11 for a
staged release couldn't seal its state key to it. Signing happens later, in the release workflow.
