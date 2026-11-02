# Product telemetry

The product's services export traces, metrics and logs over OTLP to a collector an admin sets on the
box, on :8443's **Telemetry** page in the product's section, or with `<product> telemetry` in the
closed shell. No bundle carries a collector: the box keeps the settings on its encrypted state
volume and hands them to the product. Export is off until an admin turns it on.

> **Warning:** with **Verify the certificate** off, traces and metrics go to a collector whose
> identity isn't checked. Anyone on the path between the box and the collector can read them, or
> pose as the collector. No logs leave while verification is off. Use a certificate the box trusts
> wherever the collector supports it.

## Before you update

The Telemetry page comes with base `0.1.0-rc.7`. A product bundle that reads the telemetry settings
is sealed for that base or newer, so update the base first. On an older base the product update is
refused before anything is decrypted or applied (`UPGRADE_PRODUCT_BASE`), and the Updates page and
the update's result say to update the base first; the product keeps running as it was
([release.md](release.md#the-base-a-productyaml-needs)).

## The settings

| Setting | Default | Meaning |
|---|---|---|
| Export | off | Off stops the export and keeps the endpoint. |
| Endpoint | (none) | `https://<host>[:<port>]`, the collector's OTLP gRPC address, normally port 4317. `http://`, a bare `host:port` and other schemes are refused. With no port, 443. |
| Verify the certificate | on | Checks the collector's certificate. Off skips the CA and certificate checks. |
| Logs | off | Exports logs as well as traces and metrics. Turning them on is written to the audit entry and logged as a warning. |

Saving needs a step-up and is audited as `product.telemetry.set`, with every setting and
`logs_turned_on`. With export on, the box first shakes hands with the collector over TLS, checking
its certificate unless verification is off; if that fails nothing is saved and the answer is
`TELEMETRY_UNREACHABLE`. A save is refused while an import step runs, and an open elevated shell
refuses it as it refuses a product update (an owner may override).

## How a change reaches the services

A change that alters what the services read writes the `sneakers-telemetry` ConfigMap and, while
export is on, a NetworkPolicy that opens the collector's port for the MCP server, whose own policy
doesn't reach a collector. Then, once k0s has applied them, the services restart in the order of the
product's phases, without the product stopping:

1. Each phase's workloads restart together. A workload the cluster doesn't have, such as the MCP
   server with its switch off, is left out.
2. The next phase starts once every workload of this one has rolled out. A phase has 5 minutes.
3. A phase that doesn't come back stops the run. Later phases keep the old settings, and the page
   shows the phase and the workload with a **Retry**, audited as `product.telemetry.restart`, which
   carries on from that phase. A restart a reboot cut off shows the same way.

The maintenance gate holds for the run. The audit service restarts with `Recreate`, so it's down for
its restart; the others overlap. A change that alters nothing the services read, such as a new
endpoint while export is off, saves without a restart.

## What each service is doing

The page and `<product> telemetry` show each service as `sending`, `issue`, `off` or `unknown`. The
box reads them from the gateway's `GET /telemetry-status` through the API server's service proxy, so
they can't be read while the gateway is down, and that's all that means. A collector that's down
shows as `issue` and doesn't fail the product's readiness.

## What leaves the box

Logs are default-deny on top of what each service logs: only named fields leave, values are scrubbed,
free text from target systems leaves as a class or code, and debug and trace never leave. Audit
entries, secret values and session content are never exported. What this doesn't stop is a value
with no recognisable shape inside an allowed field; the allow-list keeps those fields to ids, counts
and classes. stdout logs and the support bundle don't change.

## How the product reads them

`product.yaml` declares what the product reads ([release.md](release.md#productyaml)):

```yaml
telemetry:
  label: Traces, metrics and logs from every service
  status: sneakers/sneakers-gateway:9100   # read through the service proxy
  egress: [sneakers/sneakers-mcp]          # opened for the collector's port
  restart:                                 # in the order of the phases
    - sneakers/deployment/sneakers-identity
box_settings:
  - configmap: sneakers/sneakers-telemetry
    keys:
      - {key: OTEL_EXPORTER_OTLP_ENDPOINT, setting: telemetry.endpoint}
      - {key: OTLP_INSECURE_SKIP_VERIFY, setting: telemetry.skip_verify}
      - {key: OTLP_LOGS_ENABLED, setting: telemetry.logs}
```

Every workload in `restart` must be in a phase. Each service loads the ConfigMap whole through
`envFromConfigMaps`.

## An example collector

An OpenTelemetry Collector, run beside the box, never on it:

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
        tls:
          cert_file: /etc/otel/collector.crt
          key_file: /etc/otel/collector.key
exporters:
  debug: {}
service:
  pipelines:
    traces: {receivers: [otlp], exporters: [debug]}
    metrics: {receivers: [otlp], exporters: [debug]}
    logs: {receivers: [otlp], exporters: [debug]}
```
