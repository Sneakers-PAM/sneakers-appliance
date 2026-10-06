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
