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
| `.cmdline` | `sneakers.roothash=<hex> sneakers.hashoffset=<bytes> sneakers.version=<ver> quiet console=tty0 console=ttyS0 fbcon=font:TER16x32 panic=10 lockdown=integrity` |
| `.osrel`, `.uname` | the release's os-release and kernel release |
| `.sbat` | the shim line and `sneakers-pam,1`, so a bad release can be revoked by generation |

### Consoles

`console=tty0 console=ttyS0` turns on both the screen (the VT on the UEFI framebuffer: efifb and
fbcon) and the first serial port. The kernel writes its own messages to both, but it points
`/dev/console` at the last one, ttyS0, and that's what PID 1 starts with. On a VM with a screen and
no serial port (VMware's default) ttyS0 is still in the list and still opens, but every read and
write fails with EIO, so nothing from userspace would reach the screen. Init therefore doesn't use
`/dev/console` as it is: it opens every console in `/sys/class/tty/console/active`, keeps the ones
that take writes, and joins its standard input, output and error to them
([init.md](init.md#the-console)). `quiet` stays: the kernel's own log isn't shown, and the first
thing on the screen is init's.

It then refuses the image unless it carries exactly those six payload sections: `internal/ukipcr`
predicts PCR 11 only for them, and a box that can't predict PCR 11 for a
staged release couldn't seal its state key to it. Signing happens later, in the release workflow,
whose sign job first adds the update key as a seventh section, `.updkey`, that systemd-stub doesn't
measure and the PCR 11 prediction skips ([release.md](release.md)).
