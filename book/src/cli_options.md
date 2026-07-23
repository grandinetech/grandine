## CLI options

The list of command line options:

```
      --args-file <YAML_FILE>
          Load command-line options from a YAML file. Keys are long option names (e.g. `http-port`)
      --network <NETWORK>
          Name of the Eth2 network to connect to [default: mainnet] [possible values: mainnet, sepolia, holesky, hoodi, custom]
      --configuration-file <YAML_FILE>
          Load configuration from YAML_FILE
      --configuration-directory <DIRECTORY>
          Load configuration from directory
      --verify-phase0-preset-file <YAML_FILE>
          Verify that Phase 0 variables in preset match YAML_FILE
      --verify-altair-preset-file <YAML_FILE>
          Verify that Altair variables in preset match YAML_FILE
      --verify-bellatrix-preset-file <YAML_FILE>
          Verify that Bellatrix variables in preset match YAML_FILE
      --verify-capella-preset-file <YAML_FILE>
          Verify that Capella variables in preset match YAML_FILE
      --verify-deneb-preset-file <YAML_FILE>
          Verify that Deneb variables in preset match YAML_FILE
      --verify-electra-preset-file <YAML_FILE>
          Verify that Electra variables in preset match YAML_FILE
      --verify-fulu-preset-file <YAML_FILE>
          Verify that Fulu variables in preset match YAML_FILE
      --verify-configuration-file <YAML_FILE>
          Verify that configuration matches YAML_FILE
      --terminal-total-difficulty-override <DIFFICULTY>
          Override TERMINAL_TOTAL_DIFFICULTY
      --terminal-block-hash-override <BLOCK_HASH>
          Override TERMINAL_BLOCK_HASH
      --terminal-block-hash-activation-epoch-override <EPOCH>
          Override TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH
      --deposit-contract-starting-block <BLOCK_NUMBER>
          Start tracking deposit contract from BLOCK_NUMBER
      --genesis-state-file <SSZ_FILE>
          Load genesis state from SSZ_FILE
      --genesis-state-download-url <URL>
          Download genesis state from specified URL
      --max-empty-slots <MAX_EMPTY_SLOTS>
          Max empty slots [default: 32]
      --max-events <MAX_EVENTS>
          Max number of events stored in a single channel for HTTP API /events api call [default: 100]
      --checkpoint-sync-url <CHECKPOINT_SYNC_URL>
          Beacon node API URL to load recent finalized checkpoint and sync from it [default: None]
      --data-availability-window <DATA_AVAILABILITY_WINDOW>
          Number of epochs to keep blob or data column sidecars available for peer requests. Overrides `Config::min_epochs_for_blob_sidecars_requests` and `Config::min_epochs_for_data_column_sidecars_requests`. Intended primarily for testing. Use with caution
      --force-checkpoint-sync
          Force checkpoint sync. Requires --checkpoint-sync-url [default: disabled]
      --force-reset-beacon-db
          Forcefully deletes the existing local beacon node databases on startup, allowing a fresh sync. WARNING: This is destructive and will remove local eth1, beacon_fork_choice, sync, pubkey_cache databases. [default: disabled]
      --eth1-rpc-urls <ETH1_RPC_URLS>...
          List of Eth1 RPC URLs
      --data-dir <DATA_DIR>
          Parent directory for application data files [default: $HOME/.grandine/{network}]
      --store-directory <STORE_DIRECTORY>
          Directory to store application data files [default: {data_dir}/beacon]
      --network-dir <NETWORK_DIR>
          Directory to store application network files [default: {data_dir}/network]
      --archival-epoch-interval <ARCHIVAL_EPOCH_INTERVAL>
          Archival epoch interval [default: 32]
      --archive-storage
          Enable archival storage mode, where all blocks, states (every --archival-epoch-interval epochs) and blobs are stored in the database [default: disabled]
      --prune-storage
          Enable prune storage mode, where only a single checkpoint state and block are stored in the database [default: disabled]
      --unfinalized-states-in-memory <UNFINALIZED_STATES_IN_MEMORY>
          Number of unfinalized states to keep in memory [default: 128]
      --database-size <DATABASE_SIZE>
          Max size of the Eth2 database [default: "1.0 TiB"]
      --eth1-database-size <ETH1_DATABASE_SIZE>
          Max size of the Eth1 database [default: "16.0 GiB"]
      --reconstruction-delay <RECONSTRUCTION_DELAY>
          Default data column reconstruction delay in milliseconds for nodes serving more than half of the available data columns [default: 250]
      --request-timeout <REQUEST_TIMEOUT>
          Default global request timeout for various services in milliseconds [default: 30000]
      --max-epochs-to-retain-states-in-cache <MAX_EPOCHS_TO_RETAIN_STATES_IN_CACHE>
          Max amount of epochs to retain beacon states in state cache [default: 8]
      --state-cache-lock-timeout <STATE_CACHE_LOCK_TIMEOUT>
          Default state cache lock timeout in milliseconds [default: 1500]
      --state-slot <STATE_SLOT>
          State slot [default: None]
      --semi-supernode
          Run in semi-supernode mode, subscribing to half of the data column subnets [aliases: --subscribe-half-data-column-subnets]
      --supernode
          Run in supernode mode, subscribing to all data column subnets [aliases: --subscribe-all-data-column-subnets]
      --subscribe-all-subnets
          Subscribe to all attestation and sync committee subnets. This option does not include data column subnets
      --suggested-fee-recipient <EXECUTION_ADDRESS>
          Suggested value for the feeRecipient field of the new payload
      --jwt-id <JWT_ID>
          Optional CL unique identifier to send to EL in the JWT token claim [default: None]
      --jwt-secret <JWT_SECRET>
          Path to a file containing the hex-encoded 256 bit secret key to be used for verifying/generating JWT tokens
      --jwt-version <JWT_VERSION>
          Optional CL node type/version to send to EL in the JWT token claim [default: None]
      --back_sync
          [DEPRECATED] Enable syncing historical data [default: disabled]
      --back-sync
          Enable syncing historical data. When used with --archive-storage, it will back-sync to genesis and reconstruct historical states. When used without --archive-storage, it will back-sync blocks to the `Config::min_epochs_for_block_requests` epoch. [default: disabled]
      --metrics
          Collect Prometheus metrics
      --metrics-address <METRICS_ADDRESS>
          Metrics address for metrics endpoint [default: 127.0.0.1]
      --metrics-port <METRICS_PORT>
          Listen port for metrics endpoint [default: 5054]
      --metrics-update-interval <METRICS_UPDATE_INTERVAL>
          Update system metrics every n seconds [default: 5]
      --remote-metrics-url <REMOTE_METRICS_URL>
          Optional remote metrics (beaconcha.in metrics) URL that Grandine will periodically send metrics to
      --telemetry-level <TELEMETRY_LEVEL>
          The default tracing level controlling how detailed telemetry output will be [default: INFO]
      --telemetry-metrics-url <TELEMETRY_METRICS_URL>
          Optional OTLP metrics gRPC URL that Grandine will submit tracing and span data to. WARNING: This feature is experimental, unstable, and subject to change. Use with caution
      --telemetry-service-name <TELEMETRY_SERVICE_NAME>
          Optional OTLP service name [default: Grandine]
      --track-liveness
          Enable validator liveness tracking [default: disabled]
      --detect-doppelgangers
          Enable doppelganger protection (liveness tracking must be enabled for this feature) [default: disabled]
      --in-memory
          Enable in-memory mode. No data will be stored in data-dir. [default: disabled]
      --kzg-backend <KZG_BACKEND>
          KZG backend [default: blst]
      --blacklisted-blocks <BLACKLISTED_BLOCKS>
          A list beacon block roots that beacon node rejects unconditionally
      --sync-without-reconstruction
          Disable reconstruction while syncing the chain [default: disabled]
      --disable-http-api
          Run Grandine without HTTP API server
      --http-address <HTTP_ADDRESS>
          HTTP API address [default: 127.0.0.1]
      --http-port <HTTP_PORT>
          HTTP API port [default: 5052]
      --http-allowed-origins <HTTP_ALLOWED_ORIGINS>
          List of Access-Control-Allow-Origin header values for the HTTP API server. Defaults to the listening URL of the HTTP API server
      --timeout <TIMEOUT>
          HTTP API timeout in milliseconds [default: 1000000]
      --listen-address <LISTEN_ADDRESS>
          Listen IPv4 address [default: 0.0.0.0, unless --disable-ipv4 is set]
      --listen-address-ipv6 <LISTEN_ADDRESS_IPV6>
          Listen IPv6 address [default: None]
      --libp2p-port <LIBP2P_PORT>
          libp2p IPv4 port [default: 9000]
      --libp2p-port-ipv6 <LIBP2P_PORT_IPV6>
          libp2p IPv6 port [default: 9050]
      --disable-quic
          Disable QUIC support as a fallback transport to TCP
      --disable-peer-scoring
          Disable peer scoring
      --disable-rate-limiting
          Disable rate limiting both inbound and outbound
      --disable-upnp
          Disable NAT traversal via UPnP [default: enabled]
      --disable-enr-auto-update
          Disable enr auto update [default: enabled]
      --disable-ipv4
          Disable listening on IPv4 [default: enabled]
      --discovery-port <DISCOVERY_PORT>
          discv5 IPv4 port [default: 9000]
      --discovery-port-ipv6 <DISCOVERY_PORT_IPV6>
          discv5 IPv6 port [default: 9050]
      --quic-port <QUIC_PORT>
          QUIC IPv4 port [default: 9001]
      --quic-port-ipv6 <QUIC_PORT_IPV6>
          QUIC IPv6 port [default: 9051]
      --enable-private-discovery
          Enable discovery of peers with private IP addresses. [default: disabled]
      --enr-address <ENR_ADDRESS>
          ENR IPv4 address
      --enr-address-ipv6 <ENR_ADDRESS_IPV6>
          ENR IPv6 address
      --enr-tcp-port <ENR_TCP_PORT>
          ENR TCP IPv4 port
      --enr-tcp-port-ipv6 <ENR_TCP_PORT_IPV6>
          ENR TCP IPv6 port
      --enr-udp-port <ENR_UDP_PORT>
          ENR UDP IPv4 port
      --enr-udp-port-ipv6 <ENR_UDP_PORT_IPV6>
          ENR UDP IPv6 port
      --enr-quic-port <ENR_QUIC_PORT>
          ENR QUIC IPv4 port
      --enr-quic-port-ipv6 <ENR_QUIC_PORT_IPV6>
          ENR QUIC IPv6 port
      --boot-nodes <BOOT_NODES>
          List of ENR boot node addresses
      --libp2p-nodes <LIBP2P_NODES>
          List of Multiaddr node addresses
      --libp2p-private-key-file <KEY_FILE>
          Load p2p private key from KEY_FILE
      --target-peers <TARGET_PEERS>
          Target number of network peers [default: 200]
      --target-subnet-peers <TARGET_SUBNET_PEERS>
          Target number of subnet peers [default: 3]
      --trusted-peers <TRUSTED_PEERS>
          List of trusted peers
      --keystore-dir <KEYSTORE_DIR>
          Path to a directory containing EIP-2335 keystore files
      --keystore-password-dir <KEYSTORE_PASSWORD_DIR>
          Path to a directory containing passwords for keystore files
      --keystore-password-file <KEYSTORE_PASSWORD_FILE>
          Path to a file containing password for keystore files
      --keystore-storage-password-file <KEYSTORE_STORAGE_PASSWORD_FILE>
          Path to a file containing password for decrypting imported keystores from API
      --builder-format <BUILDER_API_FORMAT>
          Data format for communication with the builder API [default: Ssz]
      --builder-api-url <BUILDER_API_URL>
          [DEPRECATED] External block builder API URL
      --builder-url <BUILDER_URL>
          External block builder URL
      --builder-disable-checks
          Always use specified external block builder without checking for circuit breaker conditions
      --builder-max-skipped-slots <BUILDER_MAX_SKIPPED_SLOTS>
          Max allowed consecutive missing blocks to trigger circuit breaker condition and switch to local execution engine for payload construction [default: 3]
      --builder-max-skipped-slots-per-epoch <BUILDER_MAX_SKIPPED_SLOTS_PER_EPOCH>
          Max allowed missing blocks in the last rolling epoch to trigger circuit breaker condition and switch to local execution engine for payload construction [default: 8]
      --default-builder-boost-factor <DEFAULT_BUILDER_BOOST_FACTOR>
          Percentage multiplier to apply to the builder's payload value when choosing between a builder payload header and payload from the paired execution node [default: 100]
      --default-gas-limit <DEFAULT_GAS_LIMIT>
          Default execution gas limit for all validators [default: 60000000]
      --web3signer-public-keys <WEB3SIGNER_PUBLIC_KEYS>...
          List of public keys to use from Web3Signer
      --web3signer-refresh-keys-every-epoch
          Refetches keys from Web3Signer once every epoch. This overwrites changes done via Keymanager API
      --web3signer-api-urls <WEB3SIGNER_API_URLS>...
          [DEPRECATED] List of Web3Signer API URLs
      --web3signer-urls <WEB3SIGNER_URLS>...
          List of Web3Signer URLs
      --use-validator-key-cache
          Use validator key cache for faster startup
      --slashing-protection-history-limit <SLASHING_PROTECTION_HISTORY_LIMIT>
          Number of epochs to keep slashing protection data for [default: 256]
      --report-validator-performance
          Print reports about validator performance
      --no-custody-groups-backfill
          Backfill custody groups
      --disable-wait-for-late-blocks
          Disable additional 1 second wait before attesting for late blocks that are being processed at the start of the attest duty
      --enable-validator-api
          Enable validator API
      --validator-api-address <VALIDATOR_API_ADDRESS>
          Validator API address [default: 127.0.0.1]
      --validator-api-port <VALIDATOR_API_PORT>
          Listen port for validator API [default: 5055]
      --validator-api-allowed-origins <VALIDATOR_API_ALLOWED_ORIGINS>
          List of Access-Control-Allow-Origin header values for the validator API server. Defaults to the listening URL of the validator API server
      --validator-api-timeout <VALIDATOR_API_TIMEOUT>
          Validator API timeout in milliseconds [default: 10000]
      --validator-api-token-file <VALIDATOR_API_TOKEN_FILE>
          Path to a file containing validator API auth token
      --graffiti <GRAFFITI>
          Default block graffiti. Blockprint graffiti will be appended when sufficient space is available. See `--disable-blockprint-graffiti` to disable this behavior
      --disable-blockprint-graffiti
          Disable appending blockprint graffiti. If specified, no blockprint graffiti will be appended
      --features <FEATURES>
          List of optional runtime features to enable
  -h, --help
          Print help
  -V, --version
          Print version
```
