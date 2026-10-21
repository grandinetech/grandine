# Metrics

Grandine can expose metrics in the [Prometheus](https://prometheus.io/) text format and push
client statistics to a remote service such as [beaconcha.in](https://beaconcha.in). Use metrics to
watch sync progress, peer counts, resource usage and validator duty timings, and to build alerts.

This page covers the Prometheus endpoint, the bundled Grafana dashboards, remote metrics, and the
experimental OpenTelemetry tracing export. For a checklist of what to watch for validators, see
[Monitoring validator performance](./validator_monitoring.md).

## Enable the metrics endpoint

Metrics are disabled by default. Enable them with `--metrics`:

```bash
grandine \
  --network mainnet \
  --eth1-rpc-urls http://EL-HOST:8551 \
  --jwt-secret /path/to/jwt.hex \
  --metrics
```

Grandine then serves `GET /metrics` on `127.0.0.1:5054`. Check it with:

```bash
curl -s http://127.0.0.1:5054/metrics | head
```

On startup, the log shows `metrics server is listening on 127.0.0.1:5054`.

By default the endpoint listens only on localhost. If Prometheus runs on another machine or in
another container, bind it to an address Prometheus can reach:

```bash
grandine --network mainnet --metrics --metrics-address 0.0.0.0 --metrics-port 5054 ...
```

> **Warning:** The metrics endpoint has no authentication, and it allows requests from any origin
> (CORS). Do not expose port 5054 to the internet. Bind it to a private interface or restrict it
> with a firewall. See [Security best practices](./security.md).

Grandine refuses to start if the metrics port is in use, or if any two of the HTTP API, metrics
endpoint and validator API are set to the same address and port.

### Docker

Inside a container the endpoint must listen on `0.0.0.0` to be reachable from outside it. Publish
the port on the host's loopback interface only:

```bash
docker run -d --name grandine \
  -p 9000:9000/tcp -p 9000:9000/udp -p 9001:9001/udp \
  -p 127.0.0.1:5054:5054 \
  -v $HOME/.grandine:/root/.grandine \
  sifrai/grandine:stable \
  --network mainnet \
  --eth1-rpc-urls http://EL-HOST:8551 \
  --jwt-secret /root/.grandine/jwt.hex \
  --metrics \
  --metrics-address 0.0.0.0
```

If Prometheus runs in the same Docker network, it can scrape `grandine:5054` directly, and you
do not need to publish the port at all.

## Beacon node and validator client metrics

Which metrics appear depends on how you run Grandine:

| Mode | Metrics exposed |
| --- | --- |
| `grandine` (beacon node with the integrated validator client) | All metrics: beacon node, networking (libp2p, gossipsub, discovery), validator client, process and system. |
| `grandine bn` (beacon node only) | The same set. Validator duty metrics stay at zero because there are no validators. |
| `grandine vc` (separate validator client) | Only validator client metrics, process and system metrics, and the validator API response times. No fork choice, networking, HTTP API or Eth1 metrics. |

A separate validator client reports `beacon_clock_slot` from its own slot clock, so you can still
tell whether its clock is ticking. It has no `beacon_head_slot`: watch the head on the beacon nodes
it uses.

If you run a separate validator client on the same host as a beacon node, give each process its
own metrics port, for example `--metrics-port 5064` for the validator client, and scrape both:

```bash
grandine vc \
  --network hoodi \
  --beacon-node-urls http://127.0.0.1:5052 \
  --keystore-dir /path/to/keystores \
  --keystore-password-file /path/to/password.txt \
  --metrics \
  --metrics-port 5064
```

See [Validator client](./validator_client.md) for running the validator client separately.

## Useful metrics

Grandine exports several hundred series. These are a good starting point for dashboards and alerts:

| Metric | Meaning |
| --- | --- |
| `IS_LIVE` | Set to 1 when Grandine serves `/metrics`. |
| `GRANDINE_VERSION` | Version information as labels. |
| `beacon_clock_slot` | The current slot according to the local clock. |
| `beacon_head_slot` | The slot of the head block (beacon node only). |
| `beacon_finalized_epoch`, `beacon_current_justified_epoch` | Finality progress (beacon node only). |
| `beacon_reorgs_total` | Number of chain reorganizations (beacon node only). |
| `beacon_current_active_validators` | Active validators on the network (beacon node only). |
| `libp2p_peers` | Connected peers (beacon node only). |
| `GRANDINE_USED_MEMORY`, `GRANDINE_TOTAL_CPU_PERCENTAGE`, `GRANDINE_THREAD_COUNT` | Resource use of the Grandine process. |
| `SYSTEM_USED_MEMORY`, `SYSTEM_TOTAL_MEMORY`, `SYSTEM_CPU_PERCENTAGE` | Resource use of the whole machine. |
| `GRANDINE_DISK_USAGE` | Size of the beacon, network and validator directories. |
| `JEMALLOC_BYTES_ALLOCATED`, `JEMALLOC_BYTES_RESIDENT`, ... | Allocator statistics (not on Windows). See [Performance and memory tuning](./performance_tuning.md). |
| `VALIDATOR_PROPOSE_SUCCESSES` | Blocks proposed by local validators. |
| `VALIDATOR_ATTEST_TIMES`, `VALIDATOR_PROPOSE_TIMES` | How long duties take. |
| `ETH1_API_ERRORS_COUNT` | Failed requests to the execution client (beacon node only). |
| `HTTP_API_RESPONSE_TIMES`, `VALIDATOR_API_RESPONSE_TIMES` | API latency, labelled by endpoint. |

Grandine refreshes process and system metrics every `--metrics-update-interval` seconds (default
5), but only if `/metrics` was scraped since the previous refresh. A scrape interval shorter than
or equal to the update interval keeps them current.

## Prometheus configuration

Add a scrape job to `prometheus.yml`:

```yaml
global:
  scrape_interval: 12s

scrape_configs:
  - job_name: grandine
    static_configs:
      - targets: ["127.0.0.1:5054"]
        labels:
          node: grandine-mainnet-1
```

To scrape a beacon node and a separate validator client, list both targets:

```yaml
scrape_configs:
  - job_name: grandine-bn
    static_configs:
      - targets: ["127.0.0.1:5054"]
  - job_name: grandine-vc
    static_configs:
      - targets: ["127.0.0.1:5064"]
```

Reload Prometheus, then open its **Status > Targets** page and check that the targets are **UP**.

A simple alert that fires when the head stops advancing:

```yaml
groups:
  - name: grandine
    rules:
      - alert: GrandineHeadNotAdvancing
        expr: increase(beacon_head_slot[5m]) == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Grandine head slot has not advanced for 5 minutes"
```

## Grafana dashboards

The repository ships Grafana dashboards in
[`prometheus_metrics/dashboards`](https://github.com/grandinetech/grandine/tree/develop/prometheus_metrics/dashboards).
Each one except `traces.json` has an `Instance` variable, filled from the `instance` label, so a
single dashboard can show several Grandine processes.

| File | Title | What it shows |
| --- | --- | --- |
| `overview.json` | Overview | Liveness, clock and head slots, finality, CPU and memory of Grandine and the host, thread counts, dedicated executor tasks, jemalloc statistics, internal collection lengths, network traffic, disk usage, and chain data such as active validators, deposits, reorgs and participation. Start here. |
| `network.json` | Network | Peers by client and transport, NAT status, libp2p and discovery bandwidth, RPC errors and timeouts, gossipsub mesh health, per-topic traffic, peer scores and penalties. |
| `peerdas.json` | PeerDAS metrics | Data column sidecar processing and verification, `engine_getBlobsV2` calls to the execution client, custody groups and backfill, column reconstruction, cell computation, and data column gossip and req/resp traffic. See [PeerDAS and blob data](./peerdas.md). |
| `attestations.json` | Attestation | The attestation verifier, fork choice handling of attestations and aggregates, and the validator client's attestation and aggregation duty timings. |
| `proposals.json` | Proposal metrics | Proposal successes and timings, block building, local execution payloads, and preparation of the operations that go into a block. |
| `fork_choice.json` | Grandine Fork Choice / Mutator | Fork choice task timings and block insertion and processing times. |
| `pools.json` | Pools | Attestation, sync committee and BLS-to-execution-change pools, plus collection lengths of internal components. |
| `transition_functions.json` | Transition functions | State transition timings: block, blinded block, slot and epoch processing. |
| `ticks.json` | Ticks | How late the validator client's propose, attest and aggregate ticks fire. |
| `api_responses.json` | Grandine API Response times | Response times and request counts of the metrics endpoint, the validator API and the Beacon Node API. |
| `remote.json` | Remote API | Calls to the execution client, Web3Signer and the builder API: counts, errors and latency. |
| `traces.json` | Traces & Spans | Spans from the OpenTelemetry export (see below). It needs a Tempo data source, not Prometheus. |

### Import a dashboard

1. Download the JSON file from the repository, or use your local checkout.
2. In Grafana, open **Dashboards > New > Import**.
3. Upload the JSON file, or paste its content, and click **Load**.
4. Pick the folder, then click **Import**.

The panels reference a data source of type `prometheus` without a fixed UID, so Grafana uses your
default Prometheus data source. If you have several, make the right one the default, or edit the
data source of the panels after import.

To provision the dashboards automatically, copy the files into a directory Grafana loads dashboards
from:

```yaml
# /etc/grafana/provisioning/dashboards/grandine.yml
apiVersion: 1
providers:
  - name: grandine
    type: file
    options:
      path: /var/lib/grafana/dashboards/grandine
```

```bash
sudo mkdir -p /var/lib/grafana/dashboards/grandine
sudo cp prometheus_metrics/dashboards/*.json /var/lib/grafana/dashboards/grandine/
sudo systemctl restart grafana-server
```

## Remote metrics and beaconcha.in

Grandine can push client statistics to a remote endpoint that accepts the beaconcha.in client
stats format. With it, the beaconcha.in website and mobile app show your node's sync status, peer
count, CPU, memory and disk use, and validator counts, and can send you notifications, for example
by email when the node goes offline.

1. Sign in to beaconcha.in and create an API key at
   [beaconcha.in/api/key-management](https://beaconcha.in/api/key-management).
2. Start Grandine with `--remote-metrics-url`. The `machine` parameter is optional and names the
   host when you monitor more than one:

```bash
grandine \
  --network mainnet \
  --remote-metrics-url "https://beaconcha.in/api/v1/client/metrics?apikey=API-KEY&machine=MACHINE-NAME" \
  ...
```

See beaconcha.in's [machine metrics documentation](https://docs.beaconcha.in/api/machine-metrics-overview)
for the endpoint, rate limits and the number of machines your plan allows.

`--remote-metrics-url` works without `--metrics`. Grandine posts a JSON array to the URL once a
minute, with a 10 second request timeout. The array holds one object per process type, each with
`version`, `timestamp` and `process` fields:

- `beaconnode`, when Grandine runs a beacon node: CPU seconds, process memory, client name, version
  and build time, beacon database size, libp2p traffic, peer count, whether the execution client is
  connected, whether the node is synced, head slot, and whether the slasher is active.
- `validator`: the process fields plus the number of local validators and how many are active.
- `system`: CPU cores and times, memory, disk space and I/O, network traffic, boot time and OS.

A separate validator client sends the `validator` and `system` objects only.

Successful posts are logged as `metrics sent to external service`. Failures are logged as
`received error while sending external metrics`. Credentials embedded in the URL are redacted in
logs.

## OpenTelemetry tracing (experimental)

Grandine can export tracing spans to an OpenTelemetry collector over OTLP gRPC, for example to
Grafana Tempo. This is meant for developers and performance analysis. It is experimental and may
change.

```bash
grandine \
  --network hoodi \
  --telemetry-metrics-url http://OTLP-HOST:4317 \
  --telemetry-level debug \
  --telemetry-service-name grandine-hoodi \
  ...
```

`--telemetry-level` and `--telemetry-service-name` require `--telemetry-metrics-url`. The
`GRANDINE_TRACE_LOG` environment variable adds filter directives for exported spans, in the same
format as `GRANDINE_LOG` (see [Logging](./logging.md)). The trace level can also be changed at
runtime with `POST /eth/v2/debug/tracing/trace_level`. Import `traces.json` into Grafana to view
the spans.

## Command line options

See [Command line reference](./cli_options.md) for the full list.

- `--metrics`: default disabled. Collects Prometheus metrics and serves them on `/metrics`.
- `--metrics-address`: default `127.0.0.1`. Address of the metrics endpoint.
- `--metrics-port`: default `5054`. Port of the metrics endpoint.
- `--metrics-update-interval`: default `5`. How often, in seconds, process and system metrics are refreshed.
- `--remote-metrics-url`: default none. URL that receives beaconcha.in-style client stats once a minute.
- `--telemetry-metrics-url`: default none. OTLP gRPC endpoint for tracing spans (experimental).
- `--telemetry-level`: default `INFO`. Span level for the telemetry export. Requires `--telemetry-metrics-url`.
- `--telemetry-service-name`: default `Grandine`. OTLP service name. Requires `--telemetry-metrics-url`.
