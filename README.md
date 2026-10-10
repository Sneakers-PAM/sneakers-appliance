# sneakers-appliance 📦

> 🧭 Signed single-node k0s appliance OS and build kit for Sneakers-PAM

The appliance is a read-only, org-signed operating system that runs Sneakers-PAM on k0s, on one
box. `sneakers-kit` turns an org-signed release into an ISO, OVA, qcow2, Raspberry Pi or raw disk
image, and refuses anything unsigned or modified.

## 🛠 Develop

```bash
task build    # go build ./...
task test     # go test ./...
task lint     # gofmt check + golangci-lint + yamllint
task license  # check Apache-2.0 headers (golic)
```

## 🚀 Build an image

```bash
sneakers-kit verify sneakers-os:0.1.0
sneakers-kit build sneakers-os:0.1.0 --format ova --out ./out
```

## 📚 Where to look

- [docs/build-your-image.md](docs/build-your-image.md): getting the kit, verifying and building.
- [docs/formats.md](docs/formats.md), [docs/secure-boot.md](docs/secure-boot.md),
  [docs/key-custody.md](docs/key-custody.md): what you install and how it's protected.
- [docs/artifact.md](docs/artifact.md), [docs/boot.md](docs/boot.md), [docs/init.md](docs/init.md),
  [docs/upgrades.md](docs/upgrades.md): how the release and the box work.
- [docs/access.md](docs/access.md), [docs/osadmin-api.md](docs/osadmin-api.md): who gets in, and the
  :8443 appliance admin, its factory reset quorum and update flows.
- [docs/product-email.md](docs/product-email.md): the Email page, the product's mail relay.
- [docs/import.md](docs/import.md): the Import page, which brings an earlier install's export into
  the product before its own setup (imported-users mode).
- [docs/factory-reset.md](docs/factory-reset.md): how init reboots, shuts down and factory resets
  the box, and why a reset can't leave it unbootable.
- [docs/ssh-and-elevation.md](docs/ssh-and-elevation.md): key-only SSH, sshd's rendered config and
  elevation.
- [docs/console.md](docs/console.md): the console's large font, first boot's info screens, the
  status screen and Recover access.
- [docs/building.md](docs/building.md), [docs/root-image.md](docs/root-image.md),
  [docs/testing.md](docs/testing.md): building the OS, its root image and bundle, and testing it.
- [CONTRIBUTING.md](CONTRIBUTING.md): how changes land here.

## 🙏 Acknowledgements

Sneakers-PAM was originally written by [@Bugs5382](https://github.com/Bugs5382).

## 🔐 Export compliance

Sneakers-PAM is published from the United States and uses only standard, publicly available
cryptography; see [CRYPTO.md](CRYPTO.md). You are responsible for complying with applicable
export control and sanctions laws, including not using, exporting or re-exporting it in violation
of those laws or if you are on a restricted-party list.

## ⚖️ License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
