# sneakers-init

`sneakers-init` is PID 1 on the box. It decides the boot phase, unlocks the state, and supervises
the service table. There's no systemd.

## Boot phases

Decided on every boot from what the firmware reports and the recorded Secure Boot choice (the
LUKS2 header once first boot fixed it, the ESP's `loader/sneakers/secure-boot` before that):

| Facts | Phase |
|---|---|
| booted from the install medium | `install` |
| set to Secure Boot on, past enrolment, and the firmware doesn't enforce (or no longer has Secure Boot variables) | `mismatch`: the console shows the mismatch screen and nothing starts |
| no Secure Boot firmware, or Secure Boot off by choice | `firstboot`, or `normal` once setup is done |
| Secure Boot firmware and no choice yet, or on but not enforcing with org-only keys (including turned on later, before the keys are enrolled) | `enrol` |
| on, enforcing, org-only keys | `firstboot`, or `normal` once setup is done |

`firstboot` runs until `/var/lib/sneakers/setup/done` exists; init then moves to `normal` without a
reboot.

## The service table

One YAML file per service in `/usr/lib/sneakers/services.d/<name>.yaml` (read-only root):

```yaml
exec: /usr/bin/k0s                 # absolute path
args: [controller, --enable-worker]
phases: [normal]                   # install, enrol, firstboot, normal
after: [platformd]                 # started once these are ready
restart: always                    # always, on-failure (default) or never
readiness:                         # a file that appears, or a command that exits 0
  file: /run/sneakers/k0s.ready
  timeout: 2m
start: always                      # always (default) or on-demand
pre-start: [/usr/libexec/sneakers/platformd, prepare]
```

- Entering a phase stops the services that don't run in it and starts the `start: always` ones that
  do, in `after:` order, each once its dependencies are ready.
- `start: on-demand` services start and stop only when asked (the Services API), and only in
  their phases.
- `pre-start` runs to completion before every start; a non-zero exit keeps the service from
  starting (`SERVICE_PRE_START`) and its restart policy decides whether it's tried again.
- A service that exits is restarted by its policy with a backoff from 1 to 30 seconds. Stopping
  sends SIGTERM, then SIGKILL after 10 seconds.
- An entry that doesn't parse, an unknown `after:` name or a loop is `SERVICE_TABLE_INVALID`, and
  the table isn't used.
