# Build your image

The project publishes signed build inputs, never install media. You build the image you install
with `sneakers-kit`, which refuses anything the org didn't sign or that was changed after signing.

This page, and the registry references in it, are about `sneakers-kit` itself: the developer build
tool that turns a signed release into install media. They are not the running appliance's own update
path, which is the signed `.bin` package downloaded from a GitHub Release or uploaded by hand
([upgrades.md](upgrades.md)).

## 1. Get the kit

- **Container (developer tool):** `ghcr.io/sneakers-pam/sneakers-appliance-kit:<version>`, which
  carries `qemu-img` for the OVA and qcow2 formats. This is the kit image, built and published for
  convenience; it is not something the appliance itself ever pulls.
- **From source:** check out the release tag and build `cmd/sneakers-kit` with the release workflow's
  pins (`docs/kit.md`). A kit built without its pins refuses to start.

Check which keys your kit trusts:

```sh
sneakers-kit version
```

## 2. Verify the release

```sh
sneakers-kit verify sneakers-os:0.1.0
```

`<ref>` can be `sneakers-os:<version>`, a `sha256:` digest of the org's artifact, any registry
reference, or an OCI layout directory copied in for an offline site. These are inputs to the build
kit, resolved by the person building the image; they are a separate thing from the signed `.bin` the
appliance itself downloads or is given at upgrade time. `--arch arm64` verifies the arm64 release;
`--plain-http` talks plain HTTP to a lab registry on loopback.

## 3. Build

```sh
sneakers-kit build sneakers-os:0.1.0 --format ova --out ./out
```

| Flag | Meaning |
|---|---|
| `--format` | `raw`, `ova`, `qcow2`, `iso` or `rpi` ([formats.md](formats.md)) |
| `--arch` | `amd64` (the default) or `arm64` (`rpi` and `raw` only) |
| `--disk-size` | the installed disk's size, at least `64G` (`32G` for `rpi`); the default is `64G` |
| `--out` | where the output goes; a refused or failed build leaves it as it was |
| `--plain-http` | talk plain HTTP to the registry (a lab registry on loopback only) |

The build fetches the release by digest once, verifies that copy, and writes the image from exactly
the bytes it verified.

## 4. Install

- **VMware (OVA):** import the OVA. Before the first power-on, delete the PK in the VM's firmware
  setup, then follow the console ([secure-boot.md](secure-boot.md)).
- **Proxmox VE (qcow2):** follow the generated `proxmox-vm.md`.
- **QEMU or another KVM host (raw):** attach the raw disk with OVMF.
