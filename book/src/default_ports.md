# Default ports and paths

This page lists the ports Grandine listens on and the files it creates, with the options that change
them. Use it when you set up a firewall, port forwarding, Docker port mappings, or backups.

## Ports

### Peer-to-peer (beacon node only)

These ports must be reachable from the internet for good peer connectivity. Forward them on your
router, or let UPnP do it (UPnP is on by default; turn it off with `--disable-upnp`).

| Port | Protocol | Purpose | Option |
|---|---|---|---|
| 9000 | TCP | libp2p (IPv4) | `--libp2p-port` |
| 9000 | UDP | discv5 peer discovery (IPv4) | `--discovery-port` |
| 9001 | UDP | libp2p over QUIC (IPv4) | `--quic-port` |
| 9050 | TCP | libp2p (IPv6) | `--libp2p-port-ipv6` |
| 9050 | UDP | discv5 peer discovery (IPv6) | `--discovery-port-ipv6` |
| 9051 | UDP | libp2p over QUIC (IPv6) | `--quic-port-ipv6` |

- Grandine listens on IPv4 (`0.0.0.0`) by default. The IPv6 ports are used only when you set
  `--listen-address-ipv6`. Then Grandine listens on both. Add `--disable-ipv4` for IPv6 only.
- QUIC is a fallback transport to TCP. Turn it off with `--disable-quic`.
- If your public ports differ from the local ones (for example behind NAT with port translation),
  advertise the public ones with `--enr-tcp-port`, `--enr-udp-port`, `--enr-quic-port` and their
  `-ipv6` variants, and the public address with `--enr-address` or `--enr-address-ipv6`.

### APIs (local by default)

These ports bind to `127.0.0.1` by default. Do not expose them to the internet. See
[Security best practices](./security.md).

| Port | Protocol | Purpose | Enabled | Address and port options |
|---|---|---|---|---|
| 5052 | TCP (HTTP) | Beacon Node API | By default in `grandine` and `grandine bn`; turn off with `--disable-http-api` | `--http-address`, `--http-port` |
| 5054 | TCP (HTTP) | Prometheus metrics at `/metrics` | With `--metrics` | `--metrics-address`, `--metrics-port` |
| 5055 | TCP (HTTP) | Validator API, including the Keymanager API | With `--enable-validator-api` | `--validator-api-address`, `--validator-api-port` |

A separate validator client (`grandine vc`) does not open the P2P ports or the Beacon Node API. It
opens only the metrics port and the validator API port, if you enable them.

### Ports Grandine connects to

| Port | Purpose | Option |
|---|---|---|
| 8551 (usual EL default) | Execution client Engine API, authenticated with the JWT secret | `--eth1-rpc-urls`, `--jwt-secret` |
| 5052 (usual BN default) | Remote beacon nodes used by `grandine vc` | `--beacon-node-urls` |
| 18550 (usual MEV-Boost default) | Builder API | `--builder-url` |

The port numbers in this table are the other software's usual defaults, not Grandine settings.

### Port conflicts

Before starting, Grandine checks that every port it needs is free. If one is taken, it stops with:

```text
libp2p port (9000) is unavailable; make sure no other instance of the application is running or specify a different port with --libp2p-port (error: ...)
```

It also refuses to start if two of its own APIs are set to the same address and port
(`identical addresses specified for HTTP API and Metrics API`).

### Docker port mappings

Publish the P2P ports. Publish the API ports only to the host's loopback interface:

```bash
docker run -d --name grandine \
  -p 9000:9000/tcp -p 9000:9000/udp -p 9001:9001/udp \
  -p 127.0.0.1:5052:5052 \
  -v $HOME/.grandine:/root/.grandine \
  -v /path/to/jwt.hex:/jwt.hex:ro \
  sifrai/grandine:stable \
  --network hoodi \
  --http-address 0.0.0.0 \
  --eth1-rpc-urls http://EL-HOST:8551 \
  --jwt-secret /jwt.hex
```

Inside a container the API must listen on `0.0.0.0` to be reachable through a published port. The
`127.0.0.1:` prefix on `-p` keeps it private to the host.

## Paths

### Data directory

All data lives under one directory per network:

```text
DATA_DIR/NETWORK
```

- `DATA_DIR` is `$HOME/.grandine` unless you set `--data-dir`. In the official Docker image Grandine
  runs as `root`, so it is `/root/.grandine`.
- `NETWORK` is the network's configuration name: `mainnet`, `sepolia`, `holesky`, `hoodi`, or, for a
  custom network, the `CONFIG_NAME` from its `config.yaml` (`default` if the file has none).
- Grandine always appends the network name, even with `--data-dir`. For example,
  `--data-dir /var/lib/grandine --network hoodi` stores data in `/var/lib/grandine/hoodi`.
- With `--in-memory` nothing is written to disk.

### Layout

```text
$HOME/.grandine/
├── exception.log                      # internal exception log (rotated at 1 GB, 5 kept, gzipped)
└── mainnet/                           # DATA_DIR/NETWORK
    ├── meta.json                      # application name and database schema version
    ├── beacon/                        # --store-directory
    │   ├── beacon_fork_choice/        # main beacon database (libmdbx)
    │   ├── eth1_cache/                # deposit contract data
    │   ├── sync/                      # block sync service data (back-sync progress)
    │   ├── pubkey_cache/              # validator public key cache
    │   └── genesis_state.ssz          # downloaded genesis state (Sepolia, Holesky, Hoodi)
    ├── network/                       # --network-dir
    │   ├── key                        # libp2p private key (node identity)
    │   ├── enr.dat                    # local ENR
    │   └── metadata                   # libp2p metadata
    ├── validator/                     # validator data
    │   ├── slashing_protection.sqlite # slashing protection database
    │   ├── validators.yml             # validator definitions and per-validator settings
    │   ├── api-token.txt              # validator API token (with --enable-validator-api)
    │   ├── 0xPUBKEY/keystore.json     # keystores imported through the Keymanager API
    │   └── keystores.json             # encrypted key storage (with --keystore-storage-password-file)
    └── secrets/                       # passwords of keystores imported through the Keymanager API
        └── 0xPUBKEY
```

Notes:

- `exception.log` is written to the parent data directory (`$HOME/.grandine` or `--data-dir`), not
  to the per-network directory. The main log goes to standard output. See [Logging](./logging.md).
- The `beacon/` and `network/` directories exist only where a beacon node runs. A separate validator
  client (`grandine vc`) creates only `validator/` and `secrets/`.
- Keystores loaded with `--keystore-dir` stay where they are. Grandine reads them but does not copy
  them into `validator/`.
- With `--use-validator-key-cache`, an encrypted key cache file is also stored in `validator/`.
- Older versions kept `slashing_protection.sqlite` in `beacon/`. Grandine moves it to `validator/`
  automatically on startup.

### What to back up

| Path | Why | Can it be recreated? |
|---|---|---|
| `validator/slashing_protection.sqlite` | Prevents double signing. | No. Export it with `grandine interchange export` before moving validators. See [Slashing protection](./slashing_protection.md). |
| `validator/validators.yml` | Per-validator settings. | Only by hand. |
| `validator/` keystores and `secrets/` | Keys imported through the Keymanager API. | Only from your original keys. |
| `network/key` | Keeps the same peer ID across reinstalls. | Yes, a new one is generated. |
| `beacon/` | The beacon database. | Yes, by syncing again (checkpoint sync takes minutes). |

### Changing the paths

| Option | Changes |
|---|---|
| `--data-dir` | The parent of all per-network directories, and the location of `exception.log`. |
| `--store-directory` | Only the `beacon/` directory. |
| `--network-dir` | Only the `network/` directory. |
| `--libp2p-private-key-file` | The libp2p key file to load. |
| `--validator-api-token-file` | The validator API token file. |

To move an existing installation, stop Grandine, move the whole `DATA_DIR` (or the per-network
directory), and start it again with the new `--data-dir`. Make sure the user that runs Grandine owns
the files. See [Running as a service](./running_as_a_service.md).

## Command line options

- `--libp2p-port` (default `9000`): libp2p TCP port (IPv4).
- `--discovery-port` (default `9000`): discv5 UDP port (IPv4).
- `--quic-port` (default `9001`): QUIC UDP port (IPv4).
- `--libp2p-port-ipv6`, `--discovery-port-ipv6`, `--quic-port-ipv6` (defaults `9050`, `9050`, `9051`): the IPv6 equivalents.
- `--listen-address` (default `0.0.0.0`) and `--listen-address-ipv6` (default none): listen addresses.
- `--disable-quic`, `--disable-upnp`, `--disable-ipv4`: turn off QUIC, UPnP, or IPv4 listening.
- `--http-address` / `--http-port` (default `127.0.0.1:5052`): Beacon Node API.
- `--metrics-address` / `--metrics-port` (default `127.0.0.1:5054`): metrics server.
- `--validator-api-address` / `--validator-api-port` (default `127.0.0.1:5055`): validator API.
- `--data-dir` (default `$HOME/.grandine`): parent data directory.
- `--store-directory` (default `DATA_DIR/NETWORK/beacon`): beacon databases.
- `--network-dir` (default `DATA_DIR/NETWORK/network`): networking files.

See the [Command line reference](./cli_options.md) for all options.
