# Command line reference

```bash
grandine --help
grandine bn --help
grandine vc --help
```

## Modes and where options go

Grandine is a single binary that runs in one of three modes, plus a few tool subcommands.

| Command | What runs | Option groups it accepts |
|---|---|---|
| `grandine` | The beacon node. If validator keys are given, the built-in validator client runs in the same process. | General, Chain, Metrics, Telemetry, Block production, all beacon node groups, all validator groups (but not the `vc`-only "Beacon nodes" group) |
| `grandine bn` | Only the beacon node. Validator options are refused. | General, Chain, Metrics, Telemetry, Block production, all beacon node groups |
| `grandine vc` | Only the validator client, which performs its duties through one or more remote beacon nodes. Beacon node options are refused. | General, Chain (shared part), Metrics, Telemetry, Block production (shared part), Validator, Validator keys, Validator API, Beacon nodes |
| `grandine db-info`, `db-stats`, `export`, `replay`, `interchange` | One-shot tools. See [Subcommands and tools](./subcommands.md). | The same options as `grandine`, given before the subcommand name |

Rules for placing options:

- With `bn` and `vc`, every option must come **after** the mode name. An option given before it is
  refused with the error `--OPTION must be specified after bn` (or `vc`), because it would
  otherwise be parsed for the plain `grandine` mode and silently dropped.

  ```bash
  # Correct
  grandine bn --network hoodi --eth1-rpc-urls http://EL-HOST:8551 --jwt-secret /path/to/jwt.hex

  # Refused: --network is given before bn
  grandine --network hoodi bn
  ```

- With the tool subcommands, global options such as `--network` and `--data-dir` come **before** the
  subcommand, and the subcommand's own arguments come after it:

  ```bash
  grandine --network hoodi interchange export slashing_protection.json
  grandine --network hoodi db-info --database sync
  ```

- `vc` refuses options that only the built-in beacon node acts on (for example
  `--checkpoint-sync-url`, `--target-peers`, `--builder-url`, `--disable-wait-for-late-blocks`), and
  `bn` refuses validator options (for example `--keystore-dir`, `--enable-validator-api`,
  `--report-validator-performance`). Plain `grandine` refuses the `vc`-only options
  `--beacon-node-urls`, `--publish-to-every-node` and `--use-builder`.

### Value syntax

- Flags (options without a value) are off unless given: `--back-sync`.
- Some list options take several values after one flag, some take a comma-separated list, and some
  must be repeated. The tables below say which. For example:
  - `--eth1-rpc-urls URL1 URL2` (space-separated; commas are not accepted)
  - `--boot-nodes ENR1,ENR2` (comma-separated)
  - `--graffiti TEXT1 --graffiti TEXT2` (repeat the flag)
  - `--beacon-node-urls URL1,URL2` or `--beacon-node-urls URL1 URL2` (both work)
- Sizes such as `--database-size` accept values like `512GiB`, `2TiB` or `500GB`.
- URLs with credentials are redacted in Grandine's logs.

### Loading options from a file

`--args-file YAML_FILE` loads options from a flat YAML mapping whose keys are long option names
(without `--`). It is covered in [Configuration files and custom networks](./configuration_files.md#keeping-command-line-options-in-a-file).
Options given on the command line override the same option in the file.

## General

Options shared by every mode.

| Option | Default | Description | Available in |
|---|---|---|---|
| `--args-file <YAML_FILE>` | none | Load command line options from a YAML file. Keys are long option names (for example `network`). | grandine, bn, vc |
| `--features <FEATURES>` | none | Comma-separated list of optional runtime features to enable. See [Runtime features](./runtime_features.md). | grandine, bn, vc |
| `--data-dir <DATA_DIR>` | `$HOME/.grandine` | Parent directory for application data. Grandine always appends the network name, so the effective directory is `DATA_DIR/NETWORK` (for example `$HOME/.grandine/mainnet`). | grandine, bn, vc |
| `--request-timeout <REQUEST_TIMEOUT>` | `30000` | Default timeout in milliseconds for outgoing HTTP requests (execution client, checkpoint sync, Web3Signer, remote beacon nodes) and for the metrics server. | grandine, bn, vc |
| `--in-memory` | disabled | Keep all data in memory. Nothing is written to the data directory, and everything is lost on exit. Intended for testing. | grandine, bn, vc |
| `-h`, `--help` | | Print help. | grandine, bn, vc |
| `-V`, `--version` | | Print the version. | grandine |

## Chain

Options that select the network and its configuration.

| Option | Default | Description | Available in |
|---|---|---|---|
| `--network <NETWORK>` | `mainnet` | Network to connect to. Possible values: `mainnet`, `sepolia`, `holesky`, `hoodi`, `custom`. `custom` requires `--configuration-file` or `--configuration-directory`. | grandine, bn, vc |
| `--configuration-file <YAML_FILE>` | none | Load the chain configuration (`config.yaml`) from `YAML_FILE`. | grandine, bn, vc |
| `--configuration-directory <DIRECTORY>` | none | Load the chain configuration, genesis state, deposit contract block and boot nodes from a directory. See [Configuration files](./configuration_files.md). | grandine, bn, vc |
| `--genesis-state-file <SSZ_FILE>` | none | Load the genesis state from `SSZ_FILE`. | grandine, bn, vc |
| `--genesis-state-download-url <URL>` | built-in URL per network | Download the genesis state from this URL instead of the default one. Only used for predefined networks whose genesis state is not built in (Sepolia, Holesky, Hoodi). | grandine, bn |
| `--verify-phase0-preset-file <YAML_FILE>` | none | Verify that the Phase 0 preset variables match `YAML_FILE`. | grandine, bn, vc |
| `--verify-altair-preset-file <YAML_FILE>` | none | Verify that the Altair preset variables match `YAML_FILE`. | grandine, bn, vc |
| `--verify-bellatrix-preset-file <YAML_FILE>` | none | Verify that the Bellatrix preset variables match `YAML_FILE`. | grandine, bn, vc |
| `--verify-capella-preset-file <YAML_FILE>` | none | Verify that the Capella preset variables match `YAML_FILE`. | grandine, bn, vc |
| `--verify-deneb-preset-file <YAML_FILE>` | none | Verify that the Deneb preset variables match `YAML_FILE`. | grandine, bn, vc |
| `--verify-electra-preset-file <YAML_FILE>` | none | Verify that the Electra preset variables match `YAML_FILE`. | grandine, bn, vc |
| `--verify-fulu-preset-file <YAML_FILE>` | none | Verify that the Fulu preset variables match `YAML_FILE`. | grandine, bn, vc |
| `--verify-configuration-file <YAML_FILE>` | none | Verify that the loaded chain configuration matches `YAML_FILE`. | grandine, bn, vc |
| `--terminal-total-difficulty-override <DIFFICULTY>` | none | Override `TERMINAL_TOTAL_DIFFICULTY`. | grandine, bn |
| `--terminal-block-hash-override <BLOCK_HASH>` | none | Override `TERMINAL_BLOCK_HASH`. | grandine, bn |
| `--terminal-block-hash-activation-epoch-override <EPOCH>` | none | Override `TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH`. | grandine, bn |

Notes:

- When both `--configuration-directory` and `--configuration-file` (or `--genesis-state-file`) are
  given, the explicit file wins and Grandine logs a warning.
- The three `--terminal-*` overrides are applied after the verification options run.

## Beacon node

Options of the beacon node. They are refused by `grandine vc`.

| Option | Default | Description | Available in |
|---|---|---|---|
| `--eth1-rpc-urls <ETH1_RPC_URLS>...` | none | Execution client Engine API URLs (for example `http://EL-HOST:8551`). Several URLs can follow one flag, separated by spaces; Grandine switches to the next one if a request fails. Required when validators are attached. See [Connecting an execution client](./execution_client.md). | grandine, bn |
| `--jwt-secret <JWT_SECRET>` | none | Path to a file with the hex-encoded 256-bit secret shared with the execution client. | grandine, bn |
| `--jwt-id <JWT_ID>` | none | Optional consensus client identifier to send in the JWT `id` claim. | grandine, bn |
| `--jwt-version <JWT_VERSION>` | none | Optional consensus client type and version to send in the JWT `clv` claim. | grandine, bn |
| `--checkpoint-sync-url <CHECKPOINT_SYNC_URL>` | none | Beacon API URL to load a recent finalized checkpoint from. Ignored if a local database already exists. See [Checkpoint sync](./checkpoint_sync.md). | grandine, bn |
| `--force-checkpoint-sync` | disabled | Checkpoint sync even if a local database exists. Requires `--checkpoint-sync-url`. | grandine, bn |
| `--state-slot <STATE_SLOT>` | latest stored state | Start from the closest stored state at or before this slot. | grandine, bn |
| `--back-sync` | disabled | Sync historical data. With `--archive-storage`, back-syncs to genesis and reconstructs historical states. Without it, back-syncs blocks to the `MIN_EPOCHS_FOR_BLOCK_REQUESTS` window. Conflicts with `--prune-storage`. See [Back-sync and archive nodes](./historical_data.md). | grandine, bn |
| `--sync-without-reconstruction` | disabled | Disable data column reconstruction while syncing the chain. | grandine, bn |
| `--reconstruction-delay <RECONSTRUCTION_DELAY>` | `250` | Data column reconstruction delay in milliseconds for nodes that custody more than half of the data columns. | grandine, bn |
| `--supernode` | disabled | Subscribe to all data column subnets and custody all columns. Alias: `--subscribe-all-data-column-subnets`. Conflicts with `--semi-supernode`. See [PeerDAS](./peerdas.md). | grandine, bn |
| `--semi-supernode` | disabled | Subscribe to half of the data column subnets. Alias: `--subscribe-half-data-column-subnets`. Conflicts with `--supernode`. | grandine, bn |
| `--subscribe-all-subnets` | disabled | Subscribe to all attestation and sync committee subnets. Does not include data column subnets. | grandine, bn |
| `--no-custody-groups-backfill` | disabled (backfill on) | Do not backfill data columns for newly added custody groups. | grandine, bn |
| `--track-liveness` | disabled | Track validator liveness. Required for `--detect-doppelgangers` with the built-in validator client. | grandine, bn |
| `--kzg-backend <KZG_BACKEND>` | `blst` | KZG library to use. Possible values: `arkworks`, `blst`, `constantine`, `mcl`, `zkcrypto`; only backends compiled into the binary work (release builds include `blst`). | grandine, bn |
| `--deposit-contract-starting-block <BLOCK_NUMBER>` | from network or `deposit_contract_block.txt` | Execution block to start tracking the deposit contract from. Takes precedence over the value in `--configuration-directory`. | grandine, bn |
| `--blacklisted-blocks <BLACKLISTED_BLOCKS>` | none | Beacon block root that the node rejects unconditionally. Repeat the flag for several roots. | grandine, bn |

## Storage

Database and directory options of the beacon node. See [Storage and database](./storage.md).

| Option | Default | Description | Available in |
|---|---|---|---|
| `--store-directory <STORE_DIRECTORY>` | `DATA_DIR/NETWORK/beacon` | Directory for the beacon node databases. | grandine, bn |
| `--network-dir <NETWORK_DIR>` | `DATA_DIR/NETWORK/network` | Directory for networking files (node key, ENR). | grandine, bn |
| `--archive-storage` | disabled | Archive mode: store all blocks, blobs, and a state every `--archival-epoch-interval` epochs. Conflicts with `--prune-storage`. | grandine, bn |
| `--prune-storage` | disabled | Prune mode: keep only a single checkpoint state and block. Conflicts with `--archive-storage` and `--back-sync`. | grandine, bn |
| `--archival-epoch-interval <ARCHIVAL_EPOCH_INTERVAL>` | `32` | Number of epochs between stored states. Must be greater than 0. | grandine, bn |
| `--store-payloads` | disabled | Keep execution payloads of finalized blocks in the database. | grandine, bn |
| `--zstd-compression-level <ZSTD_COMPRESSION_LEVEL>` | `3` | zstd compression level for finalized blocks and execution payloads in the database. Other data is compressed with Snappy. Negative values are allowed; the value must be within the range zstd supports (at most 22). | grandine, bn |
| `--database-size <DATABASE_SIZE>` | `1 TiB` | Maximum size of the beacon (Eth2) database map. If it fills up, Grandine restarts with a doubled limit. | grandine, bn |
| `--eth1-database-size <ETH1_DATABASE_SIZE>` | `16 GiB` | Maximum size of the Eth1 (deposit) database map. | grandine, bn |
| `--unfinalized-states-in-memory <UNFINALIZED_STATES_IN_MEMORY>` | `128` | Number of unfinalized states to keep in memory. Must be at least 2 epochs of slots (64 on mainnet presets). | grandine, bn |
| `--max-epochs-to-retain-states-in-cache <MAX_EPOCHS_TO_RETAIN_STATES_IN_CACHE>` | `8` | Maximum number of epochs to keep beacon states in the state cache. | grandine, bn |
| `--state-cache-lock-timeout <STATE_CACHE_LOCK_TIMEOUT>` | `1500` | State cache lock timeout in milliseconds. | grandine, bn |
| `--data-availability-window <DATA_AVAILABILITY_WINDOW>` | from chain config | Number of epochs to keep blob and data column sidecars available for peer requests. Overrides `MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS` and `MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS`. Intended for testing. Conflicts with `--archive-storage` and `--prune-storage`. | grandine, bn |
| `--force-reset-beacon-db` | disabled | Delete the local `eth1`, `beacon_fork_choice`, `sync` and `pubkey_cache` databases on startup for a fresh sync. Destructive. | grandine, bn |

## HTTP API

The Beacon Node API server. See [Beacon Node API](./beacon_node_api.md).

| Option | Default | Description | Available in |
|---|---|---|---|
| `--disable-http-api` | disabled (API on) | Run without the HTTP API server. | grandine, bn |
| `--http-address <HTTP_ADDRESS>` | `127.0.0.1` | HTTP API listen address. | grandine, bn |
| `--http-port <HTTP_PORT>` | `5052` | HTTP API listen port. | grandine, bn |
| `--http-allowed-origins <HTTP_ALLOWED_ORIGINS>` | `http://HTTP_ADDRESS:HTTP_PORT` | Comma-separated list of `Access-Control-Allow-Origin` values. `*` allows any origin. | grandine, bn |
| `--timeout <TIMEOUT>` | `1000000` | HTTP API request timeout in milliseconds (1000 seconds). | grandine, bn |
| `--max-events <MAX_EVENTS>` | `100` | Maximum number of events buffered per channel for `/eth/v1/events`. | grandine, bn |

## Networking

Peer-to-peer networking options. See [Networking and peers](./networking.md) and
[Default ports](./default_ports.md).

| Option | Default | Description | Available in |
|---|---|---|---|
| `--listen-address <LISTEN_ADDRESS>` | `0.0.0.0` | IPv4 listen address (unless `--disable-ipv4`). | grandine, bn |
| `--listen-address-ipv6 <LISTEN_ADDRESS_IPV6>` | none | IPv6 listen address. Setting it enables dual-stack listening. | grandine, bn |
| `--disable-ipv4` | disabled | Do not listen on IPv4. Requires `--listen-address-ipv6`. Conflicts with `--listen-address`, `--enr-address`, `--enr-tcp-port`, `--enr-udp-port` and `--enr-quic-port`. | grandine, bn |
| `--libp2p-port <LIBP2P_PORT>` | `9000` | libp2p TCP port (IPv4). | grandine, bn |
| `--libp2p-port-ipv6 <LIBP2P_PORT_IPV6>` | `9050` | libp2p TCP port (IPv6). | grandine, bn |
| `--discovery-port <DISCOVERY_PORT>` | `9000` | discv5 UDP port (IPv4). | grandine, bn |
| `--discovery-port-ipv6 <DISCOVERY_PORT_IPV6>` | `9050` | discv5 UDP port (IPv6). | grandine, bn |
| `--quic-port <QUIC_PORT>` | `9001` | QUIC UDP port (IPv4). | grandine, bn |
| `--quic-port-ipv6 <QUIC_PORT_IPV6>` | `9051` | QUIC UDP port (IPv6). | grandine, bn |
| `--disable-quic` | disabled (QUIC on) | Disable QUIC, which is used as a fallback transport to TCP. | grandine, bn |
| `--disable-upnp` | disabled (UPnP on) | Disable NAT traversal through UPnP. | grandine, bn |
| `--disable-enr-auto-update` | disabled (auto-update on) | Do not update the ENR address automatically from what peers report. | grandine, bn |
| `--enable-private-discovery` | disabled | Discover peers with private IP addresses (useful for local devnets). | grandine, bn |
| `--enr-address <ENR_ADDRESS>` | none | IPv4 address to advertise in the ENR. | grandine, bn |
| `--enr-address-ipv6 <ENR_ADDRESS_IPV6>` | none | IPv6 address to advertise in the ENR. | grandine, bn |
| `--enr-tcp-port <ENR_TCP_PORT>` | `--libp2p-port` | TCP port (IPv4) to advertise in the ENR. | grandine, bn |
| `--enr-tcp-port-ipv6 <ENR_TCP_PORT_IPV6>` | none | TCP port (IPv6) to advertise in the ENR. | grandine, bn |
| `--enr-udp-port <ENR_UDP_PORT>` | none | discv5 UDP port (IPv4) to advertise in the ENR. | grandine, bn |
| `--enr-udp-port-ipv6 <ENR_UDP_PORT_IPV6>` | none | discv5 UDP port (IPv6) to advertise in the ENR. | grandine, bn |
| `--enr-quic-port <ENR_QUIC_PORT>` | none | QUIC port (IPv4) to advertise in the ENR. | grandine, bn |
| `--enr-quic-port-ipv6 <ENR_QUIC_PORT_IPV6>` | none | QUIC port (IPv6) to advertise in the ENR. | grandine, bn |
| `--boot-nodes <BOOT_NODES>` | network's boot nodes | Comma-separated list of ENRs to bootstrap discovery from. Replaces the built-in list. | grandine, bn |
| `--libp2p-nodes <LIBP2P_NODES>` | none | Comma-separated list of multiaddrs to connect to directly. | grandine, bn |
| `--libp2p-private-key-file <KEY_FILE>` | `NETWORK_DIR/key` | Load the libp2p private key from `KEY_FILE`. | grandine, bn |
| `--target-peers <TARGET_PEERS>` | `200` | Target number of peers. | grandine, bn |
| `--target-subnet-peers <TARGET_SUBNET_PEERS>` | `3` | Target number of peers per subnet. | grandine, bn |
| `--trusted-peers <TRUSTED_PEERS>` | none | Comma-separated list of trusted peer IDs. Peer scoring does not penalize them. | grandine, bn |
| `--disable-peer-scoring` | disabled | Disable peer scoring. | grandine, bn |
| `--disable-rate-limiting` | disabled | Disable inbound and outbound request rate limiting. | grandine, bn |

When UPnP is enabled and you also set ENR options by hand, Grandine warns that UPnP might override
them. Add `--disable-upnp` if you set the ENR yourself.

## Block production

Options for proposing blocks. The first five are shared with `grandine vc`; the rest belong to the
beacon node. See [Fee recipient, graffiti and gas limit](./fee_recipient.md) and
[Builder API and MEV](./builder_api_and_mev.md).

| Option | Default | Description | Available in |
|---|---|---|---|
| `--suggested-fee-recipient <EXECUTION_ADDRESS>` | none | Default fee recipient for proposals. Can be overridden per validator in `validators.yml`. | grandine, bn, vc |
| `--graffiti <GRAFFITI>` | none | Default block graffiti, at most 32 bytes. Repeat the flag to rotate between several values. A short blockprint graffiti is appended when space allows. | grandine, bn, vc |
| `--default-gas-limit <DEFAULT_GAS_LIMIT>` | scheduled gas limit, or `60000000` | Default execution gas limit for all validators. | grandine, bn, vc |
| `--default-builder-boost-factor <DEFAULT_BUILDER_BOOST_FACTOR>` | `100` | Scales the builder's payload value by this percentage before Grandine weighs it against the payload from the execution client. `0` always uses the local payload. | grandine, bn, vc |
| `--max-empty-slots <MAX_EMPTY_SLOTS>` | `32` | Maximum number of empty slots that a state may be advanced through to process a block or attestation, and that a validator client tolerates behind the head. | grandine, bn, vc |
| `--builder-url <BUILDER_URL>` | none | External block builder (for example MEV-Boost) URL. | grandine, bn |
| `--builder-format <BUILDER_API_FORMAT>` | `ssz` | Data format used with the builder API. Possible values: `json`, `ssz`. | grandine, bn |
| `--builder-header-timeout <BUILDER_HEADER_TIMEOUT>` | `1000` | Timeout in milliseconds for fetching an execution payload header from the builder. Must be greater than `0`. Relevant only until Gloas. | grandine, bn |
| `--builder-disable-checks` | disabled | Always use the builder, without checking circuit breaker conditions. | grandine, bn |
| `--builder-max-skipped-slots <BUILDER_MAX_SKIPPED_SLOTS>` | `3` | Consecutive missing blocks (missing payloads after Gloas) that trip the circuit breaker and switch to local payloads. | grandine, bn |
| `--builder-max-skipped-slots-per-epoch <BUILDER_MAX_SKIPPED_SLOTS_PER_EPOCH>` | `8` | Missing blocks (missing payloads after Gloas) in the last rolling epoch that trip the circuit breaker. | grandine, bn |
| `--disable-wait-for-late-blocks` | disabled | Do not wait the extra second before attesting when a block is still being processed at the start of the attestation duty. | grandine, bn |
| `--disable-blockprint-graffiti` | disabled | Do not append blockprint graffiti. | grandine, bn |

## Metrics

Prometheus metrics. See [Metrics](./metrics.md).

| Option | Default | Description | Available in |
|---|---|---|---|
| `--metrics` | disabled | Collect Prometheus metrics and serve them at `/metrics`. | grandine, bn, vc |
| `--metrics-address <METRICS_ADDRESS>` | `127.0.0.1` | Metrics server listen address. | grandine, bn, vc |
| `--metrics-port <METRICS_PORT>` | `5054` | Metrics server listen port. | grandine, bn, vc |
| `--metrics-update-interval <METRICS_UPDATE_INTERVAL>` | `5` | Update system metrics every N seconds. | grandine, bn, vc |
| `--remote-metrics-url <REMOTE_METRICS_URL>` | none | URL to push beaconcha.in-style metrics to periodically. | grandine, bn, vc |

A separate validator client (`grandine vc`) exposes only validator client metrics.

## Telemetry

OpenTelemetry (OTLP) tracing export. Experimental.

| Option | Default | Description | Available in |
|---|---|---|---|
| `--telemetry-metrics-url <TELEMETRY_METRICS_URL>` | none | OTLP gRPC URL to send tracing and span data to. Experimental and subject to change. | grandine, bn, vc |
| `--telemetry-level <TELEMETRY_LEVEL>` | `INFO` | Tracing level for telemetry output (`trace`, `debug`, `info`, `warn`, `error`). Requires `--telemetry-metrics-url`. | grandine, bn, vc |
| `--telemetry-service-name <TELEMETRY_SERVICE_NAME>` | `Grandine` | OTLP service name. Requires `--telemetry-metrics-url`. | grandine, bn, vc |

## Validator

Validator client options. See [Validator client](./validator_client.md).

| Option | Default | Description | Available in |
|---|---|---|---|
| `--detect-doppelgangers` | disabled | Enable doppelganger protection. With the built-in beacon node, `--track-liveness` is required. See [Doppelganger protection](./doppelganger_protection.md). | grandine, vc |
| `--report-validator-performance` | disabled | Print reports about the performance of the attached validators. Only works with the built-in beacon node. | grandine |
| `--slashing-protection-history-limit <SLASHING_PROTECTION_HISTORY_LIMIT>` | `256` | Number of epochs of slashing protection data to keep. | grandine, vc |

## Validator keys

Where validator keys come from. See [Managing validator keys](./key_management.md) and
[Web3Signer](./web3signer.md).

| Option | Default | Description | Available in |
|---|---|---|---|
| `--keystore-dir <KEYSTORE_DIR>` | none | Directory with EIP-2335 keystore files. Requires `--keystore-password-file` or `--keystore-password-dir`. | grandine, vc |
| `--keystore-password-file <KEYSTORE_PASSWORD_FILE>` | none | File with one password used for all keystores. Conflicts with `--keystore-password-dir`. | grandine, vc |
| `--keystore-password-dir <KEYSTORE_PASSWORD_DIR>` | none | Directory with one password file per keystore. Conflicts with `--keystore-password-file`. | grandine, vc |
| `--keystore-storage-password-file <KEYSTORE_STORAGE_PASSWORD_FILE>` | none | File with the password for the legacy `keystores.json` storage, which holds keys imported through the Keymanager API by older Grandine versions. | grandine, vc |
| `--web3signer-urls <WEB3SIGNER_URLS>...` | none | Web3Signer URLs. Several URLs can follow one flag, separated by spaces. All keys each URL serves are loaded. | grandine, vc |
| `--web3signer-public-keys <WEB3SIGNER_PUBLIC_KEYS>` | all keys | Only use these public keys from Web3Signer. Comma- or space-separated. | grandine, vc |
| `--web3signer-refresh-keys-every-epoch` | disabled | Refetch keys from Web3Signer every epoch. This overwrites changes to remote keys made through the Keymanager API. | grandine, vc |
| `--use-validator-key-cache` | disabled | Cache decrypted keys (encrypted with the keystore passwords) for faster startup. | grandine, vc |

## Validator API

The validator client's own API, which serves the Keymanager API. Disabled unless
`--enable-validator-api` is given. See [Keymanager API](./keymanager_api.md).

| Option | Default | Description | Available in |
|---|---|---|---|
| `--enable-validator-api` | disabled | Enable the validator API. | grandine, vc |
| `--validator-api-address <VALIDATOR_API_ADDRESS>` | `127.0.0.1` | Validator API listen address. | grandine, vc |
| `--validator-api-port <VALIDATOR_API_PORT>` | `5055` | Validator API listen port. | grandine, vc |
| `--validator-api-allowed-origins <VALIDATOR_API_ALLOWED_ORIGINS>` | `http://VALIDATOR_API_ADDRESS:VALIDATOR_API_PORT` | `Access-Control-Allow-Origin` values. Repeat the flag for several values. `*` allows any origin. | grandine, vc |
| `--validator-api-timeout <VALIDATOR_API_TIMEOUT>` | `10000` | Validator API request timeout in milliseconds. | grandine, vc |
| `--validator-api-token-file <VALIDATOR_API_TOKEN_FILE>` | `DATA_DIR/NETWORK/validator/api-token.txt` | File with the bearer token for the validator API. Only the default file is created if missing; a file you pass must already exist. | grandine, vc |

## Beacon nodes

Options of the separate validator client only. See [Redundancy and fallback beacon nodes](./redundancy.md).

| Option | Default | Description | Available in |
|---|---|---|---|
| `--beacon-node-urls <BEACON_NODE_URLS>` | none (required) | Beacon node API URLs to perform duties against, comma- or space-separated. Among the healthiest nodes, duties go to the one with the newest head, then to the first listed. | vc |
| `--publish-to-every-node [<PUBLISH_TO_EVERY_NODE>...]` | `all` | Duties to publish to every beacon node rather than only the first one. Possible values: `all`, `aggregates`, `attestations`, `blocks`, `payload-attestations`, `proposer-preferences`, `sync-committee-contributions`, `sync-committee-messages`. Given without a value, everything goes to the first node that accepts it. | vc |
| `--use-builder` | disabled | Use the builder behind the beacon nodes: register validators with it and accept its payloads. Without it, only local payloads are requested and builder boost factors are ignored. Relevant only until Gloas. | vc |

## Cross-option checks

Besides the `requires` and `conflicts` rules in the tables, Grandine checks these when it starts:

- `--network custom` without `--configuration-file` (or `--configuration-directory`) fails with
  `--configuration-file must be specified when connecting to custom network`.
- A custom network without `--eth1-rpc-urls` needs a genesis state:
  `--eth1-rpc-urls must be specified when connecting to custom network without --genesis-state-file`.
- Validators attached to the built-in beacon node need an execution client:
  `--eth1-rpc-urls must be specified when validators are present`.
- `--detect-doppelgangers` with the built-in beacon node needs `--track-liveness`.
- `--unfinalized-states-in-memory` must be at least two epochs of slots.
- The HTTP API, metrics and validator API must not listen on the same address and port
  (`identical addresses specified for ...`).
- Each listening port is checked before startup: `... port (PORT) is unavailable; make sure no other
  instance of the application is running or specify a different port with OPTION`.

## Deprecated options

These still work but log a deprecation warning. Use the replacement.

| Deprecated option | Replacement | Available in |
|---|---|---|
| `--back_sync` | `--back-sync` | grandine, bn |
| `--builder-api-url <URL>` | `--builder-url <URL>` (used only if `--builder-url` is not given) | grandine, bn |
| `--web3signer-api-urls <URLS>...` | `--web3signer-urls <URLS>...` (used only if `--web3signer-urls` is not given) | grandine, vc |

## Aliases

| Alias | Option |
|---|---|
| `--subscribe-all-data-column-subnets` | `--supernode` |
| `--subscribe-half-data-column-subnets` | `--semi-supernode` |

## Removed options

Grandine has no hidden options. Older documentation mentions `--slashing-enabled` and
`--slashing-history-limit` for the built-in slasher. These are no longer accepted on the command
line: the slasher is disabled in the current code. See [Slasher](./slasher.md).

## Subcommands

The tool subcommands and their own arguments are described in
[Subcommands and tools](./subcommands.md):

| Subcommand | Purpose |
|---|---|
| `bn` | Run only the beacon node. |
| `vc` | Run only the validator client against remote beacon nodes. |
| `db-info --database <beacon\|sync> [--path DIR]` | Show information about database records. |
| `db-stats [--path DIR]` | Show `beacon_fork_choice` database element sizes. |
| `export --from SLOT --to SLOT [--output-dir DIR]` | Export blocks and states in a slot range to SSZ files. |
| `replay --from SLOT --to SLOT [--input-dir DIR]` | Replay blocks in a slot range. |
| `interchange import FILE` / `interchange export FILE` | Import or export an EIP-3076 slashing protection interchange file. |
| `help` | Print help for Grandine or for a subcommand. |
