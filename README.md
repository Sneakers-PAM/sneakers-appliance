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

## 📚 Where to look

- [CONTRIBUTING.md](CONTRIBUTING.md): how changes land here.
- `docs/`: building an image, Secure Boot and the runbooks (added with each feature).

## 🙏 Acknowledgements

Sneakers-PAM was originally written by [@Bugs5382](https://github.com/Bugs5382).

## ⚖️ License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
