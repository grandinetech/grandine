# Logging

Grandine writes its log to standard output. It does not write a general log file of its own: let
your service manager (systemd and journald, or Docker) collect standard output, rotate it and keep
it. The only file Grandine writes itself is a small exception log, described below.

## Log format

Each line has, in this order, a local timestamp with milliseconds and the UTC offset (`Z` when the
local time zone is UTC), the level, the module that logged it with a line number, the message, and,
for the beacon node, the connected and target peer counts. Any other fields of the event follow the
peer counts. An illustrative line:

```text
[2026-10-19T12:00:01.234+03:00]  INFO fork_choice_control::mutator:3392: unloading old beacon states (head slot: 1234567) peers=[87/200]
```

- `peers=[87/200]` means 87 connected peers out of a target of 200 (`--target-peers`). A separate
  validator client (`grandine vc`) has no peers and leaves this field out.
- Colors (ANSI escape codes) are used only when standard output is a terminal. When output goes to
  a file, a pipe, journald or `docker logs`, the log is plain text.

At startup Grandine logs what it is running (`starting beacon node with validator client`,
`starting beacon node` or `starting validator client`) and then its effective configuration.

## Log levels

Levels from least to most verbose are `error`, `warn`, `info`, `debug` and `trace`. By default every
Grandine module logs at `info`, and everything else, including third-party libraries, is off.

There is no `--log-level` flag. Set levels with the `GRANDINE_LOG` environment variable before
start, or change them on a running node through the API (see below).

### `GRANDINE_LOG`

`GRANDINE_LOG` takes a comma-separated list of directives in the
[`tracing_subscriber::EnvFilter`](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html)
format: `target=level`, where the target is a Grandine crate (module) name. Directives are added on
top of the defaults.

```bash
# More detail from networking and fork choice
GRANDINE_LOG=p2p=debug,fork_choice_control=debug grandine --network hoodi ...

# Quieter: only warnings and errors from the validator
GRANDINE_LOG=validator=warn grandine --network hoodi ...
```

Useful targets include `grandine`, `runtime`, `p2p`, `eth2_libp2p`, `fork_choice_control`,
`fork_choice_store`, `validator`, `block_producer`, `builder_api`, `execution_engine`, `eth1_api`,
`http_api`, `keymanager`, `signer`, `slashing_protection`, `storage`, `database` and
`doppelganger_protection`.

> **Note:** Name the targets you want. A bare level such as `GRANDINE_LOG=debug` does not raise the
> Grandine modules, because their own `info` directives are more specific. It only turns on
> third-party libraries that are otherwise silent, which is very noisy.

> **Tip:** `RUST_LOG` is not read by Grandine. Use `GRANDINE_LOG`.

With systemd, set the variable in the unit:

```ini
[Service]
Environment=GRANDINE_LOG=p2p=debug
```

With Docker, pass it with `-e`:

```bash
docker run -e GRANDINE_LOG=p2p=debug sifrai/grandine:stable --network hoodi ...
```

## Change the log level at runtime

You can change log levels without restarting Grandine. A restart of a node with validators costs
missed duties, so prefer this when you need extra detail for a short time.

The endpoint takes a target and a level:

```bash
curl -X POST http://127.0.0.1:5052/eth/v2/debug/tracing/log_level \
  -H "Content-Type: application/json" \
  -d '{"target": "p2p", "level": "debug"}'
```

The response is `log level updated`. Set the level back the same way:

```bash
curl -X POST http://127.0.0.1:5052/eth/v2/debug/tracing/log_level \
  -H "Content-Type: application/json" \
  -d '{"target": "p2p", "level": "info"}'
```

Where the endpoint is served:

- **Beacon node**: on the Beacon Node API (`--http-address`, `--http-port`, default
  `127.0.0.1:5052`). It has no authentication, which is one more reason to keep the Beacon Node
  API off public interfaces. See [Beacon Node API](./beacon_node_api.md).
- **Validator client**: on the validator API (`--enable-validator-api`, default
  `127.0.0.1:5055`), behind the API token. This is how you change levels on a separate
  `grandine vc`, which has no Beacon Node API:

```bash
curl -X POST http://127.0.0.1:5055/eth/v2/debug/tracing/log_level \
  -H "Authorization: Bearer $(cat /path/to/api-token.txt)" \
  -H "Content-Type: application/json" \
  -d '{"target": "validator", "level": "debug"}'
```

See [Keymanager API](./keymanager_api.md) for where the token is stored.

Changes made this way last until the process exits. `POST /eth/v2/debug/tracing/trace_level`
works the same way for the OpenTelemetry export (see [Metrics](./metrics.md)); its `target` is
optional and it answers `telemetry not available` if `--telemetry-metrics-url` is not set.

## Logging HTTP requests

For debugging API clients, Grandine has [runtime features](./runtime_features.md) that log HTTP
traffic at `info`: `LogHttpRequests` (method, URI and remote address, plus the response status),
`LogHttpHeaders` and `LogHttpBodies`. Enable them only for a short time, as they are verbose and can
log sensitive data.

```bash
grandine --network hoodi --features LogHttpRequests ...
```

## The exception log

Grandine writes errors from a few internal code paths, marked as exceptions, to `exception.log` in
the data directory root (`$HOME/.grandine/exception.log` by default, or `--data-dir`). These are
conditions the developers want to know about. The file rotates at 1 GB, and Grandine keeps up to 5
gzip-compressed old files. It is not written in `--in-memory` mode. Attach it to bug reports.

## Viewing and keeping logs

### systemd and journald

When Grandine runs as a systemd service, journald stores its output:

```bash
# Follow the log
journalctl -u grandine -f

# The last hour, without the pager
journalctl -u grandine --since "1 hour ago" --no-pager

# Warnings and errors from the current boot
journalctl -u grandine -b --no-pager | grep -E " (WARN|ERROR) "
```

journald rotates on its own. Limit the space it uses in `/etc/systemd/journald.conf`:

```ini
[Journal]
SystemMaxUse=2G
MaxRetentionSec=14day
```

Then run `sudo systemctl restart systemd-journald`. See
[Running as a service](./running_as_a_service.md) for the unit file.

### Writing to a file with logrotate

If you want plain log files, redirect standard output in the unit:

```ini
[Service]
StandardOutput=append:/var/log/grandine/grandine.log
StandardError=append:/var/log/grandine/grandine.log
```

Rotate them with logrotate, for example in `/etc/logrotate.d/grandine`:

```text
/var/log/grandine/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

Use `copytruncate`: Grandine keeps the file open and does not reopen it on a signal.

### Docker

Read the container log with `docker logs`:

```bash
docker logs -f --tail 100 grandine
```

The default `json-file` driver does not rotate. Limit it per container:

```bash
docker run -d --name grandine \
  --log-driver json-file --log-opt max-size=100m --log-opt max-file=5 \
  sifrai/grandine:stable --network mainnet ...
```

Or in Docker Compose:

```yaml
services:
  grandine:
    image: sifrai/grandine:stable
    logging:
      driver: json-file
      options:
        max-size: "100m"
        max-file: "5"
```

## Reading the logs

Some lines worth knowing:

- `starting beacon node with validator client`: the mode Grandine started in.
- `metrics server is listening on ...` and `Validator API is listening on ...`: endpoints that are up.
- `unloading old beacon states (head slot: N)`: logged at each epoch boundary while following the
  chain. A head slot that keeps up with the network means the node is in sync.
- `metrics sent to external service`: a successful post to `--remote-metrics-url`.

For log messages that point to problems, see [Troubleshooting](./troubleshooting.md).

## Command line options

There are no logging flags. Logging is controlled by:

- `GRANDINE_LOG` (environment variable): default unset. Extra log filter directives.
- `GRANDINE_TRACE_LOG` (environment variable): default unset. Extra filter directives for the OpenTelemetry export.
- `--features LogHttpRequests,LogHttpHeaders,LogHttpBodies`: default disabled. Log HTTP traffic.

See [Command line reference](./cli_options.md) for the full list of options.
