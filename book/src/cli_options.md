## CLI options

The list of command line options:

```
      --network <NETWORK>
          Name of the Eth2 network to connect to [default: mainnet] [possible values: mainnet, goerli, custom]
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
      --max-empty-slots <MAX_EMPTY_SLOTS>
          [default: 32]
      --checkpoint-sync-url <CHECKPOINT_SYNC_URL>
          Beacon node API URL to load recent finalized checkpoint and sync from it [default: None]
      --force-checkpoint-sync
          Force checkpoint sync. Requires --checkpoint-sync-url [default: disabled]
      --eth1-rpc-urls <ETH1_RPC_URLS>...
          List of Eth1 RPC URLs
      --data-dir <DATA_DIR>
          Parent directory for application data files [default: $HOME/.grandine/{network}]
      --store-directory <STORE_DIRECTORY>
          Directory to store application data files [default: {data_dir}/beacon]
      --network-dir <NETWORK_DIR>
          Directory to store application network files [default: {data_dir}/network]
      --archival-epoch-interval <ARCHIVAL_EPOCH_INTERVAL>
          [default: 32]
      --prune-storage
          Enable prune mode where only single checkpoint state & block are stored in the DB [default: disabled]
      --unfinalized-states-in-memory <UNFINALIZED_STATES_IN_MEMORY>
          Number of unfinalized states to keep in memory. Specifying this number enables unfinalized state pruning. By default all unfinalized states are kept in memory. [default: None]
      --database-size <DATABASE_SIZE>
          Max size of the Eth2 database [default: "274.9 GB"]
      --eth1-database-size <ETH1_DATABASE_SIZE>
          Max size of the Eth1 database [default: "17.2 GB"]
      --request-timeout <REQUEST_TIMEOUT>
          Default global request timeout for various services in milliseconds [default: 30000]
      --http-address <HTTP_ADDRESS>
          HTTP API address [default: 127.0.0.1]
      --http-port <HTTP_PORT>
          HTTP API port [default: 5052]
      --state-slot <STATE_SLOT>
          State slot [default: None]
      --disable-block-verification-pool
          Disable block signature verification pool [default: enabled]
      --subscribe-all-subnets
          Subscribe to all subnets
      --suggested-fee-recipient <EXECUTION_ADDRESS>
          Suggested value for the feeRecipient field of the new payload
      --jwt-id <JWT_ID>
          Optional CL unique identifier to send to EL in the JWT token claim [default: None]
      --jwt-secret <JWT_SECRET>
          Path to a file containing the hex-encoded 256 bit secret key to be used for verifying/generating JWT tokens
      --jwt-version <JWT_VERSION>
          Optional CL node type/version to send to EL in the JWT token claim [default: None]
      --back-sync
          Enable syncing historical data [default: disabled]
      --metrics
          Collect Prometheus metrics
      --metrics-address <METRICS_ADDRESS>
          Metrics address for metrics endpoint [default: 127.0.0.1]
      --metrics-port <METRICS_PORT>
          Listen port for metrics endpoint [default: 5054]
      --remote-metrics-url <REMOTE_METRICS_URL>
          Optional remote metrics URL that Grandine will periodically send metrics to
      --track-liveness
          Enable validator liveness tracking [default: disabled]
      --max-events <MAX_EVENTS>
          Max number of events stored in a single channel for HTTP API /events api call [default: 100]
      --timeout <TIMEOUT>
          HTTP API timeout in milliseconds [default: 10000]
      --listen-address <LISTEN_ADDRESS>
          Listen IPv4 address [default: 0.0.0.0]
      --listen-address-ipv6 <LISTEN_ADDRESS_IPV6>
          Listen IPv6 address [default: None]
      --libp2p-port <LIBP2P_PORT>
          libp2p IPv4 port [default: 9000]
      --libp2p-port-ipv6 <LIBP2P_PORT_IPV6>
          libp2p IPv6 port [default: 9050]
      --disable-peer-scoring
          Disable peer scoring
      --disable-upnp
          Disable NAT traversal via UPnP [default: enabled]
      --discovery-port <DISCOVERY_PORT>
          discv5 IPv4 port [default: 9000]
      --discovery-port-ipv6 <DISCOVERY_PORT_IPV6>
          discv5 IPv6 port [default: 9050]
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
      --boot-nodes <BOOT_NODES>
          List of ENR boot node addresses
      --libp2p-nodes <LIBP2P_NODES>
          List of Multiaddr node addresses
      --target-peers <TARGET_PEERS>
          Target number of network peers [default: 80]
      --trusted-peers <TRUSTED_PEERS>
          List of trusted peers
      --slashing-enabled
          Enable slasher [default: disabled]
      --slashing-history-limit <SLASHING_HISTORY_LIMIT>
          Number of epochs for slasher to search for violations [default: 54000]
      --keystore-dir <KEYSTORE_DIR>
          Path to a directory containing EIP-2335 keystore files
      --keystore-password-dir <KEYSTORE_PASSWORD_DIR>
          Path to a directory containing passwords for keystore files
      --keystore-password-file <KEYSTORE_PASSWORD_FILE>
          Path to a file containing password for keystore files
      --pack-extra-attestations
          Pack extra singular attestations to proposed block
      --builder-api-url <BUILDER_API_URL>
          External block builder API URL
      --builder-disable-checks
          Always use specified external block builder without checking for circuit breaker conditions
      --builder-max-skipped-slots <BUILDER_MAX_SKIPPED_SLOTS>
          Max allowed consecutive missing blocks to trigger circuit breaker condition and switch to local execution engine for payload construction [default: 3]
      --builder-max-skipped-slots-per-epoch <BUILDER_MAX_SKIPPED_SLOTS_PER_EPOCH>
          Max allowed missing blocks in the last rolling epoch to trigger circuit breaker condition and switch to local execution engine for payload construction [default: 5]
      --web3signer-api-urls <WEB3SIGNER_API_URLS>...
          List of Web3Signer API URLs
      --use-validator-key-cache
          Use validator key cache for faster startup
      --graffiti <GRAFFITI>
          Custom graffiti to include in proposed blocks
      --features <FEATURES>
          List of optional runtime features to enable
  -h, --help
          Print help
  -V, --version
          Print version
```
