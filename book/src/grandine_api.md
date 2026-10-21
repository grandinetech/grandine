# Grandine-specific endpoints

Besides the standard [Beacon Node API](./beacon_node_api.md), the Grandine beacon node serves a
few endpoints that are not part of the
[Ethereum Beacon APIs specification](https://ethereum.github.io/beacon-APIs/). They give quick
status summaries, detailed validator performance reports, host resource usage, and runtime control
over features and logging.

All of them are served on the same address and port as the Beacon Node API (by default
`127.0.0.1:5052`), without authentication. The log and trace level endpoints are also served by the
validator API of a validator client, where they require the API token.

Grandine does not implement the client-specific namespaces of other clients, such as
`/lighthouse/...`, `/teku/...` or `/nimbus/...`.

> **Warning:** Several of these endpoints change how the node behaves (`PATCH /features`, the log
> and trace level endpoints) or reveal information about the host and your validators. Do not
> expose the beacon node API port to untrusted networks. See
> [Security best practices](./security.md).

## Summary

| Method | Path | Purpose | Requires |
| --- | --- | --- | --- |
| GET | `/beacon/head` | Head and finalized block summary | |
| GET | `/validator/statistics` | Per-validator performance and rewards over an epoch range | `ServeCostlyEndpoints` |
| GET | `/validator/registered` | Validators registered with the node for block building | `ServeCostlyEndpoints` |
| GET | `/validator/owned` | Validators whose keys the integrated validator client holds | `ServeCostlyEndpoints` |
| GET | `/features` | Runtime features and whether each is on | |
| PATCH | `/features` | Turn runtime features on or off without a restart | |
| GET | `/system/stats` | CPU, memory and network usage | `ServeLeakyEndpoints` and `--metrics` |
| POST | `/eth/v2/debug/tracing/log_level` | Change the log level of a component at runtime | |
| POST | `/eth/v2/debug/tracing/trace_level` | Change the OpenTelemetry trace level at runtime | `--telemetry-metrics-url` |

Endpoints that require a runtime feature return `403 Forbidden` until you enable it, either at
startup with `--features` or at runtime with `PATCH /features`:

```bash
grandine --network mainnet --features ServeCostlyEndpoints,ServeLeakyEndpoints --metrics
```

See [Runtime features](./runtime_features.md) for the full list of features.

## Head summary

`GET /beacon/head` returns the current head and the latest finalized block in one small response.
Slots are plain JSON numbers here, not strings as in the standard API.

```bash
curl -s http://127.0.0.1:5052/beacon/head | jq
```

```json
{
  "block_root": "0x...",
  "finalized_block_root": "0x...",
  "finalized_slot": 12345600,
  "slot": 12345678
}
```

`finalized_slot` is the first slot of the finalized epoch.

## Validator statistics

`GET /validator/statistics` computes a detailed performance report for validators over a range of
epochs. For each epoch it reports the network state (finalized epoch, whether the chain is in an
inactivity leak, participation statistics). For each validator it reports:

- the number of active epochs, and how many attestations had a correct source, target and head,
- the sum of inclusion delays,
- total rewards and penalties in Gwei,
- a report per epoch with proposals, attestation and sync committee assignments and performance,
  balance changes and slashing penalties.

Query parameters:

- `start`: first epoch, inclusive.
- `end`: last epoch, inclusive. If `end` is before `start`, the response is empty.
- `pubkeys[]`: optional, repeatable. Public keys of extra validators to include.

The report always covers the validators in the integrated validator client and the validators
registered through `POST /eth/v1/validator/register_validator`. Add any other validator with
`pubkeys[]`.

```bash
curl -s -g 'http://127.0.0.1:5052/validator/statistics?start=385800&end=385801&pubkeys[]=0xPUBKEY' | jq
```

`-g` stops curl from interpreting the square brackets.

Grandine computes the report by replaying the chain over the requested range, so it costs CPU and
memory, and longer ranges take longer. That is why the endpoint needs the `ServeCostlyEndpoints`
feature. Request a few epochs at a time. The response is `null` if the node no longer has the
states needed for the range, for example epochs before a checkpoint sync anchor when the node has
not back-filled them. See [Back-sync and archive nodes](./historical_data.md).

For day-to-day monitoring, metrics are cheaper. See
[Monitoring validator performance](./validator_monitoring.md).

## Registered and owned validators

`GET /validator/registered` lists the validators that the node's validator clients have registered
for external block building through `POST /eth/v1/validator/register_validator`. Use it to check
that a validator client sends its [builder registrations](./builder_api_and_mev.md) to this node.
Grandine keeps a registration for the epoch in which it arrived and the two epochs after it, and
drops it at the start of the third. A validator client that keeps registering each epoch stays
listed; one that stops drops off the list within three epochs.

`GET /validator/owned` lists the validators whose keys are loaded in the integrated validator
client of this process.

Both return a JSON object that maps public keys to validator indices. Validators that are not yet
in the beacon state (no index assigned) are left out.

```bash
curl -s http://127.0.0.1:5052/validator/owned | jq
```

```json
{
  "0xPUBKEY-1": 123456,
  "0xPUBKEY-2": 123457
}
```

Both endpoints require the `ServeCostlyEndpoints` feature.

## Runtime features

`GET /features` returns every runtime feature and whether it is enabled:

```bash
curl -s http://127.0.0.1:5052/features | jq
```

```json
{
  "AggregateAllAttestations": false,
  "AlwaysPrepackAttestations": false,
  "...": false,
  "ServeCostlyEndpoints": true,
  "ServeLeakyEndpoints": false,
  "...": false
}
```

`PATCH /features` turns features on or off without restarting. Send a JSON object with the
features to change. Features that you leave out keep their current value:

```bash
curl -s -X PATCH http://127.0.0.1:5052/features \
  -H 'Content-Type: application/json' \
  -d '{"ServeCostlyEndpoints": true, "LogHttpRequests": true}'
```

Grandine logs each change, for example `feature ServeCostlyEndpoints enabled`. Changes last until
the process restarts. To make them permanent, add them to `--features`.

Some features are read only once at startup, so changing them at runtime has no effect. For
example, `LogHttpBodies` and `PatchHttpContentType` change how the HTTP server is built. See
[Runtime features](./runtime_features.md) for what each feature does.

> **Warning:** `PATCH /features` can turn on behavior that weakens validation, such as the
> `Trust...` features, or that writes large amounts of data to disk, such as the `Dump...` features.
> Anyone who can reach the API port can call it.

## System statistics

`GET /system/stats` returns resource usage of the Grandine process and the host:

```bash
curl -s http://127.0.0.1:5052/system/stats | jq
```

The response contains `core_count`, `grandine_used_memory`, `grandine_total_cpu_percentage`,
`rx_bytes`, `tx_bytes`, `system_cpu_percentage`, `system_used_memory` and `system_total_memory`.
Memory and traffic values are in bytes.

The values come from the metrics service, so the node must run with `--metrics`. Otherwise the
endpoint answers with an error saying that the metrics service is not configured. The values are
refreshed at most every `--metrics-update-interval` seconds, and only while something scrapes
`/metrics`. Without a scraper they stay at their last values. Because the response reveals details about the
host, the endpoint also requires the `ServeLeakyEndpoints` feature. For long-term monitoring, scrape
the same data with Prometheus instead. See [Metrics](./metrics.md).

## Log and trace levels

These two endpoints change logging detail while Grandine runs, so you can collect debug output for
one component without restarting. Restarting a validator client costs at least a slot of duties,
so this is especially useful there.

### Log level

`POST /eth/v2/debug/tracing/log_level` sets the log level for one target. The body has two
required fields:

- `target`: the component, which is the name of a Grandine crate such as `fork_choice_control`,
  `p2p`, `eth2_libp2p`, `execution_engine`, `http_api`, `validator` or `block_producer`.
- `level`: `trace`, `debug`, `info`, `warn`, `error` or `off`.

```bash
curl -s -X POST http://127.0.0.1:5052/eth/v2/debug/tracing/log_level \
  -H 'Content-Type: application/json' \
  -d '{"target": "fork_choice_control", "level": "debug"}'
```

```text
log level updated
```

To go back to normal output, set the level to `info` again:

```bash
curl -s -X POST http://127.0.0.1:5052/eth/v2/debug/tracing/log_level \
  -H 'Content-Type: application/json' \
  -d '{"target": "fork_choice_control", "level": "info"}'
```

The change adds a filter directive of the form `target=level` to the running log filter. It lasts
until the process restarts. A directive that does not parse, for example because of an unknown
level, returns `400 Bad Request` with the reason. The target is not checked: a name that matches
no component is accepted and has no effect.
See [Logging](./logging.md) for log levels and output.

### Trace level

`POST /eth/v2/debug/tracing/trace_level` does the same for the spans and events that Grandine
exports over OpenTelemetry. It only works when telemetry export is enabled with
`--telemetry-metrics-url`. Otherwise it returns `503 Service Unavailable` with
`telemetry not available`.

The body has a required `level` and an optional `target`. Without a target, the level applies to
everything:

```bash
curl -s -X POST http://127.0.0.1:5052/eth/v2/debug/tracing/trace_level \
  -H 'Content-Type: application/json' \
  -d '{"level": "debug"}'
```

```bash
curl -s -X POST http://127.0.0.1:5052/eth/v2/debug/tracing/trace_level \
  -H 'Content-Type: application/json' \
  -d '{"target": "p2p", "level": "trace"}'
```

The starting level is set with `--telemetry-level` (default `INFO`).

### On a separate validator client

A validator client started with `grandine vc` has no beacon node API. It serves both endpoints on
its validator API instead, which must be enabled with `--enable-validator-api` (default address
`127.0.0.1:5055`). There the requests need the API token in an `Authorization: Bearer` header. See
[Keymanager API](./keymanager_api.md) for the token file.

```bash
curl -s -X POST http://127.0.0.1:5055/eth/v2/debug/tracing/log_level \
  -H "Authorization: Bearer $(cat /path/to/api-token.txt)" \
  -H 'Content-Type: application/json' \
  -d '{"target": "validator", "level": "debug"}'
```

The validator API of a combined beacon node and validator client (plain `grandine` with
`--enable-validator-api`) serves the same two endpoints with the token as well.

## Command line options

- `--features` (default: none): comma-separated runtime features to enable at startup, such as
  `ServeCostlyEndpoints` or `ServeLeakyEndpoints`.
- `--metrics` (default: off): run the metrics service, which `/system/stats` needs.
- `--metrics-update-interval` (default: `5`): seconds between system metric updates.
- `--telemetry-metrics-url` (default: none): OTLP endpoint for trace export, which
  `/eth/v2/debug/tracing/trace_level` needs.
- `--telemetry-level` (default: `INFO`): initial trace level for exported telemetry.
- `--http-address` (default: `127.0.0.1`) and `--http-port` (default: `5052`): where the beacon
  node serves these endpoints.
- `--enable-validator-api` (default: off), `--validator-api-address` (default: `127.0.0.1`),
  `--validator-api-port` (default: `5055`), `--validator-api-token-file` (default: a token file in
  the validator directory): the validator API, which serves the log and trace level endpoints with
  token authentication.

See [Command line reference](./cli_options.md) for all options.
