namespace Grandine.NethermindPlugin;

using System;
using Nethermind.Config;

public interface IGrandineConfig : IConfig
{
    [ConfigItem(Description = "Whether to enable embedded grandine CL", DefaultValue = "false")]
    public bool Enabled { get; set; }

    [ConfigItem(Description = "Name of the Eth2 network to connect to", DefaultValue = "mainnet")]
    [GrandineConfigItem(Name = "--network")]
    public string? Network { get; set; }

    [ConfigItem(Description = "Load configuration from YAML_FILE")]
    [GrandineConfigItem(Name = "--configuration-file")]
    public string? ConfigurationFile { get; set; }

    [ConfigItem(Description = "Load configuration from directory")]
    [GrandineConfigItem(Name = "--configuration-directory")]
    public string? ConfigurationDirectory { get; set; }

    [ConfigItem(Description = "Verify that Phase 0 variables in preset match YAML_FILE")]
    [GrandineConfigItem(Name = "--verify-phase0-preset-file")]
    public string? VerifyPhase0PresetFile { get; set; }

    [ConfigItem(Description = "Verify that Altair variables in preset match YAML_FILE")]
    [GrandineConfigItem(Name = "--verify-altair-preset-file")]
    public string? VerifyAltairPresetFile { get; set; }

    [ConfigItem(Description = "Verify that Bellatrix variables in preset match YAML_FILE")]
    [GrandineConfigItem(Name = "--verify-bellatrix-preset-file")]
    public string? VerifyBellatrixPresetFile { get; set; }

    [ConfigItem(Description = "Verify that Capella variables in preset match YAML_FILE")]
    [GrandineConfigItem(Name = "--verify-capella-preset-file")]
    public string? VerifyCapellaPresetFile { get; set; }

    [ConfigItem(Description = "Verify that Deneb variables in preset match YAML_FILE")]
    [GrandineConfigItem(Name = "--verify-deneb-preset-file")]
    public string? VerifyDenebPresetFile { get; set; }

    [ConfigItem(Description = "Verify that Electra variables in preset match YAML_FILE")]
    [GrandineConfigItem(Name = "--verify-electra-preset-file")]
    public string? VerifyElectraPresetFile { get; set; }

    [ConfigItem(Description = "Verify that configuration matches YAML_FILE")]
    [GrandineConfigItem(Name = "--verify-configuration-file")]
    public string? VerifyConfigurationFile { get; set; }

    [ConfigItem(Description = "Override TERMINAL_TOTAL_DIFFICULTY")]
    [GrandineConfigItem(Name = "--terminal-total-difficulty-override")]
    public string? TerminalTotalDifficultyOverride { get; set; }

    [ConfigItem(Description = "Override TERMINAL_BLOCK_HASH")]
    [GrandineConfigItem(Name = "--terminal-block-hash-override")]
    public string? TerminalBlockHashOverride { get; set; }

    [ConfigItem(Description = "Override TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH")]
    [GrandineConfigItem(Name = "--terminal-block-hash-activation-epoch-override")]
    public string? TerminalBlockHashActivationEpochOverride { get; set; }

    [ConfigItem(Description = "Start tracking deposit contract from BLOCK_NUMBER")]
    [GrandineConfigItem(Name = "--deposit-contract-starting-block")]
    public string? DepositContractStartingBlock { get; set; }

    [ConfigItem(Description = "Load genesis state from SSZ_FILE")]
    [GrandineConfigItem(Name = "--genesis-state-file")]
    public string? GenesisStateFile { get; set; }

    [ConfigItem(Description = "Download genesis state from specified URL")]
    [GrandineConfigItem(Name = "--genesis-state-download-url")]
    public string? GenesisStateDownloadUrl { get; set; }

    [ConfigItem(DefaultValue = "32")]
    [GrandineConfigItem(Name = "--max-empty-slots")]
    public string? MaxEmptySlots { get; set; }

    [ConfigItem(Description = "Max number of events stored in a single channel for HTTP API /events api call", DefaultValue = "100")]
    [GrandineConfigItem(Name = "--max-events")]
    public string? MaxEvents { get; set; }

    [ConfigItem(Description = "Beacon node API URL to load recent finalized checkpoint and sync from it", DefaultValue = "None")]
    [GrandineConfigItem(Name = "--checkpoint-sync-url")]
    public string? CheckpointSyncUrl { get; set; }

    [ConfigItem(Description = "Force checkpoint sync. Requires --checkpoint-sync-url", DefaultValue = "false")]
    [GrandineConfigItem(Name = "--force-checkpoint-sync")]
    public bool ForceCheckpointSync { get; set; }

    [ConfigItem(Description = "Parent directory for application data files", DefaultValue = "$HOME/.grandine/{network}")]
    [GrandineConfigItem(Name = "--data-dir")]
    public string? DataDir { get; set; }

    [ConfigItem(Description = "Directory to store application data files", DefaultValue = "{data_dir}/beacon")]
    [GrandineConfigItem(Name = "--store-directory")]
    public string? StoreDirectory { get; set; }

    [ConfigItem(Description = "Directory to store application network files", DefaultValue = "{data_dir}/network")]
    [GrandineConfigItem(Name = "--network-dir")]
    public string? NetworkDir { get; set; }

    [ConfigItem(DefaultValue = "32")]
    [GrandineConfigItem(Name = "--archival-epoch-interval")]
    public string? ArchivalEpochInterval { get; set; }

    [ConfigItem(Description = "Enable archival storage mode, where all blocks, states (every --archival-epoch-stringerval epochs) and blobs are stored in the database", DefaultValue = "false")]
    [GrandineConfigItem(Name = "--archive-storage")]
    public bool ArchiveStorage { get; set; }

    [ConfigItem(Description = "Enable prune storage mode, where only a single checkpoint state and block are stored in the database", DefaultValue = "false")]
    [GrandineConfigItem(Name = "--prune-storage")]
    public bool PruneStorage { get; set; }

    [ConfigItem(Description = "Number of unfinalized states to keep in memory", DefaultValue = "128")]
    [GrandineConfigItem(Name = "--unfinalized-states-in-memory")]
    public string? UnfinalizedStatesInMemory { get; set; }

    [ConfigItem(Description = "Max size of the Eth2 database", DefaultValue = "1.0 TiB")]
    [GrandineConfigItem(Name = "--database-size")]
    public string? DatabaseSize { get; set; }

    [ConfigItem(Description = "Max size of the Eth1 database", DefaultValue = "16.0 GiB")]
    [GrandineConfigItem(Name = "--eth1-database-size")]
    public string? Eth1DatabaseSize { get; set; }

    [ConfigItem(Description = "Default global request timeout for various services in milliseconds", DefaultValue = "30000")]
    [GrandineConfigItem(Name = "--request-timeout")]
    public string? RequestTimeout { get; set; }

    [ConfigItem(Description = "Max amount of epochs to retain beacon states in state cache", DefaultValue = "8")]
    [GrandineConfigItem(Name = "--max-epochs-to-retain-states-in-cache")]
    public string? MaxEpochsToRetainStatesInCache { get; set; }

    [ConfigItem(Description = "Default state cache lock timeout in milliseconds", DefaultValue = "1500")]
    [GrandineConfigItem(Name = "--state-cache-lock-timeout")]
    public string? StateCacheLockTimeout { get; set; }

    [ConfigItem(Description = "State slot", DefaultValue = "None")]
    [GrandineConfigItem(Name = "--state-slot")]
    public string? StateSlot { get; set; }

    [ConfigItem(Description = "Subscribe to all subnets", DefaultValue = "false")]
    [GrandineConfigItem(Name = "--subscribe-all-subnets")]
    public bool SubscribeAllSubnets { get; set; }

    [ConfigItem(Description = "Suggested value for the feeRecipient field of the new payload")]
    [GrandineConfigItem(Name = "--suggested-fee-recipient")]
    public string? SuggestedFeeRecipient { get; set; }

    [ConfigItem(Description = "Optional CL unique identifier to send to EL in the JWT token claim", DefaultValue = "None")]
    [GrandineConfigItem(Name = "--jwt-id")]
    public string? JwtId { get; set; }

    [ConfigItem(Description = "Optional CL node type/version to send to EL in the JWT token claim", DefaultValue = "None")]
    [GrandineConfigItem(Name = "--jwt-version")]
    public string? JwtVersion { get; set; }

    [ConfigItem(Description = "[DEPRECATED] Enable syncing historical data", DefaultValue = "false")]
    [GrandineConfigItem(Name = "--back_sync")]
    [Obsolete("Use BackSync instead.")]
    public bool BackSyncDeprecated { get; set; }

    [ConfigItem(Description = "Enable syncing historical data. When used with --archive-storage, it will back-sync to genesis and reconstruct historical states. When used without --archive-storage, it will back-sync blocks to the MIN_EPOCHS_FOR_BLOCK_REQUESTS epoch.", DefaultValue = "false")]
    [GrandineConfigItem(Name = "--back-sync")]
    public bool BackSync { get; set; }

    [ConfigItem(Description = "Collect Prometheus metrics", DefaultValue = "false")]
    [GrandineConfigItem(Name = "--metrics")]
    public bool Metrics { get; set; }

    [ConfigItem(Description = "Metrics address for metrics endpoint", DefaultValue = "127.0.0.1")]
    [GrandineConfigItem(Name = "--metrics-address")]
    public string? MetricsAddress { get; set; }

    [ConfigItem(Description = "Listen port for metrics endpoint", DefaultValue = "5054")]
    [GrandineConfigItem(Name = "--metrics-port")]
    public string? MetricsPort { get; set; }

    [ConfigItem(Description = "Update system metrics every n seconds", DefaultValue = "5")]
    [GrandineConfigItem(Name = "--metrics-update-interval")]
    public string? MetricsUpdateInterval { get; set; }

    [ConfigItem(Description = "Optional remote metrics URL that Grandine will periodically send metrics to")]
    [GrandineConfigItem(Name = "--remote-metrics-url")]
    public string? RemoteMetricsUrl { get; set; }

    [ConfigItem(Description = "Enable validator liveness tracking", DefaultValue = "false")]
    [GrandineConfigItem(Name = "--track-liveness")]
    public bool TrackLiveness { get; set; }

    [ConfigItem(Description = "Enable doppelganger protection (liveness tracking must be enabled for this feature)", DefaultValue = "false")]
    [GrandineConfigItem(Name = "--detect-doppelgangers")]
    public bool DetectDoppelgangers { get; set; }

    [ConfigItem(Description = "Enable in-memory mode. No data will be stored in data-dir.", DefaultValue = "false")]
    [GrandineConfigItem(Name = "--in-memory")]
    public bool InMemory { get; set; }

    [ConfigItem(DefaultValue = "blst")]
    [GrandineConfigItem(Name = "--kzg-backend")]
    public string? KzgBackend { get; set; }

    [ConfigItem(Description = "")] // Description is empty in source
    [GrandineConfigItem(Name = "--blacklisted-blocks")]
    public string? BlacklistedBlocks { get; set; } // Assuming list of block identifiers (hashes or numbers)

    [ConfigItem(Description = "HTTP API address", DefaultValue = "127.0.0.1")]
    [GrandineConfigItem(Name = "--http-address")]
    public string? HttpAddress { get; set; }

    [ConfigItem(Description = "HTTP API port", DefaultValue = "5052")]
    [GrandineConfigItem(Name = "--http-port")]
    public string? HttpPort { get; set; }

    [ConfigItem(Description = "List of Access-Control-Allow-Origin header values for the HTTP API server. Defaults to the listening URL of the HTTP API server")]
    [GrandineConfigItem(Name = "--http-allowed-origins")]
    public string? HttpAllowedOrigins { get; set; }

    [ConfigItem(Description = "HTTP API timeout in milliseconds", DefaultValue = "10000")]
    [GrandineConfigItem(Name = "--timeout")]
    public string? Timeout { get; set; }

    [ConfigItem(Description = "Listen IPv4 address", DefaultValue = "0.0.0.0")]
    [GrandineConfigItem(Name = "--listen-address")]
    public string? ListenAddress { get; set; }

    [ConfigItem(Description = "Listen IPv6 address", DefaultValue = "None")]
    [GrandineConfigItem(Name = "--listen-address-ipv6")]
    public string? ListenAddressIpv6 { get; set; }

    [ConfigItem(Description = "libp2p IPv4 port", DefaultValue = "9000")]
    [GrandineConfigItem(Name = "--libp2p-port")]
    public string? Libp2pPort { get; set; }

    [ConfigItem(Description = "libp2p IPv6 port", DefaultValue = "9050")]
    [GrandineConfigItem(Name = "--libp2p-port-ipv6")]
    public string? Libp2pPortIpv6 { get; set; }

    [ConfigItem(Description = "Disable QUIC support as a fallback transport to TCP", DefaultValue = "false")]
    [GrandineConfigItem(Name = "--disable-quic")]
    public bool DisableQuic { get; set; }

    [ConfigItem(Description = "Disable peer scoring", DefaultValue = "false")]
    [GrandineConfigItem(Name = "--disable-peer-scoring")]
    public bool DisablePeerScoring { get; set; }

    [ConfigItem(Description = "Disable NAT traversal via UPnP", DefaultValue = "false")] // CLI default says "enabled", setting property default to false means flag enables it.
    [GrandineConfigItem(Name = "--disable-upnp")]
    public bool DisableUpnp { get; set; }

    [ConfigItem(Description = "Disable enr auto update", DefaultValue = "false")] // CLI default says "enabled", setting property default to false means flag enables it.
    [GrandineConfigItem(Name = "--disable-enr-auto-update")]
    public bool DisableEnrAutoUpdate { get; set; }

    [ConfigItem(Description = "discv5 IPv4 port", DefaultValue = "9000")]
    [GrandineConfigItem(Name = "--discovery-port")]
    public string? DiscoveryPort { get; set; }

    [ConfigItem(Description = "discv5 IPv6 port", DefaultValue = "9050")]
    [GrandineConfigItem(Name = "--discovery-port-ipv6")]
    public string? DiscoveryPortIpv6 { get; set; }

    [ConfigItem(Description = "QUIC IPv4 port", DefaultValue = "9001")]
    [GrandineConfigItem(Name = "--quic-port")]
    public string? QuicPort { get; set; }

    [ConfigItem(Description = "QUIC IPv6 port", DefaultValue = "9051")]
    [GrandineConfigItem(Name = "--quic-port-ipv6")]
    public string? QuicPortIpv6 { get; set; }

    [ConfigItem(Description = "Enable discovery of peers with private IP addresses.", DefaultValue = "false")]
    [GrandineConfigItem(Name = "--enable-private-discovery")]
    public bool EnablePrivateDiscovery { get; set; }

    [ConfigItem(Description = "ENR IPv4 address")]
    [GrandineConfigItem(Name = "--enr-address")]
    public string? EnrAddress { get; set; }

    [ConfigItem(Description = "ENR IPv6 address")]
    [GrandineConfigItem(Name = "--enr-address-ipv6")]
    public string? EnrAddressIpv6 { get; set; }

    [ConfigItem(Description = "ENR TCP IPv4 port")]
    [GrandineConfigItem(Name = "--enr-tcp-port")]
    public string? EnrTcpPort { get; set; }

    [ConfigItem(Description = "ENR TCP IPv6 port")]
    [GrandineConfigItem(Name = "--enr-tcp-port-ipv6")]
    public string? EnrTcpPortIpv6 { get; set; }

    [ConfigItem(Description = "ENR UDP IPv4 port")]
    [GrandineConfigItem(Name = "--enr-udp-port")]
    public string? EnrUdpPort { get; set; }

    [ConfigItem(Description = "ENR UDP IPv6 port")]
    [GrandineConfigItem(Name = "--enr-udp-port-ipv6")]
    public string? EnrUdpPortIpv6 { get; set; }

    [ConfigItem(Description = "ENR QUIC IPv4 port")]
    [GrandineConfigItem(Name = "--enr-quic-port")]
    public string? EnrQuicPort { get; set; }

    [ConfigItem(Description = "ENR QUIC IPv6 port")]
    [GrandineConfigItem(Name = "--enr-quic-port-ipv6")]
    public string? EnrQuicPortIpv6 { get; set; }

    [ConfigItem(Description = "List of ENR boot node addresses")]
    [GrandineConfigItem(Name = "--boot-nodes")]
    public string? BootNodes { get; set; }

    [ConfigItem(Description = "List of Multiaddr node addresses")]
    [GrandineConfigItem(Name = "--libp2p-nodes")]
    public string? Libp2pNodes { get; set; }

    [ConfigItem(Description = "Load p2p private key from KEY_FILE")]
    [GrandineConfigItem(Name = "--libp2p-private-key-file")]
    public string? Libp2pPrivateKeyFile { get; set; }

    [ConfigItem(Description = "Target number of network peers", DefaultValue = "100")]
    [GrandineConfigItem(Name = "--target-peers")]
    public string? TargetPeers { get; set; }

    [ConfigItem(Description = "Target number of subnet peers", DefaultValue = "3")]
    [GrandineConfigItem(Name = "--target-subnet-peers")]
    public string? TargetSubnetPeers { get; set; }

    [ConfigItem(Description = "List of trusted peers")]
    [GrandineConfigItem(Name = "--trusted-peers")]
    public string? TrustedPeers { get; set; }

    [ConfigItem(Description = "Path to a directory containing EIP-2335 keystore files")]
    [GrandineConfigItem(Name = "--keystore-dir")]
    public string? KeystoreDir { get; set; }

    [ConfigItem(Description = "Path to a directory containing passwords for keystore files")]
    [GrandineConfigItem(Name = "--keystore-password-dir")]
    public string? KeystorePasswordDir { get; set; }

    [ConfigItem(Description = "Path to a file containing password for keystore files")]
    [GrandineConfigItem(Name = "--keystore-password-file")]
    public string? KeystorePasswordFile { get; set; }

    [ConfigItem(Description = "Path to a file containing password for decrypting imported keystores from API")]
    [GrandineConfigItem(Name = "--keystore-storage-password-file")]
    public string? KeystoreStoragePasswordFile { get; set; }

    [ConfigItem(Description = "Data format for communication with the builder API", DefaultValue = "Ssz")]
    [GrandineConfigItem(Name = "--builder-format")]
    public string? BuilderFormat { get; set; }

    [ConfigItem(Description = "[DEPRECATED] External block builder API URL")]
    [GrandineConfigItem(Name = "--builder-api-url")]
    [Obsolete("Use BuilderUrl instead.")]
    public string? BuilderApiUrl { get; set; }

    [ConfigItem(Description = "External block builder URL")]
    [GrandineConfigItem(Name = "--builder-url")]
    public string? BuilderUrl { get; set; }

    [ConfigItem(Description = "Always use specified external block builder without checking for circuit breaker conditions", DefaultValue = "false")]
    [GrandineConfigItem(Name = "--builder-disable-checks")]
    public bool BuilderDisableChecks { get; set; }

    [ConfigItem(Description = "Max allowed consecutive missing blocks to trigger circuit breaker condition and switch to local execution engine for payload construction", DefaultValue = "3")]
    [GrandineConfigItem(Name = "--builder-max-skipped-slots")]
    public string? BuilderMaxSkippedSlots { get; set; }

    [ConfigItem(Description = "Max allowed missing blocks in the last rolling epoch to trigger circuit breaker condition and switch to local execution engine for payload construction", DefaultValue = "8")]
    [GrandineConfigItem(Name = "--builder-max-skipped-slots-per-epoch")]
    public string? BuilderMaxSkippedSlotsPerEpoch { get; set; }

    [ConfigItem(Description = "Default execution gas limit for all validators", DefaultValue = "36000000")]
    [GrandineConfigItem(Name = "--default-gas-limit")]
    public string? DefaultGasLimit { get; set; }

    [ConfigItem(Description = "List of public keys to use from Web3Signer")]
    [GrandineConfigItem(Name = "--web3signer-public-keys")]
    public string? Web3signerPublicKeys { get; set; }

    [ConfigItem(Description = "Refetches keys from Web3Signer once every epoch. This overwrites changes done via Keymanager API", DefaultValue = "false")]
    [GrandineConfigItem(Name = "--web3signer-refresh-keys-every-epoch")]
    public bool Web3signerRefreshKeysEveryEpoch { get; set; }

    [ConfigItem(Description = "[DEPRECATED] List of Web3Signer API URLs")]
    [GrandineConfigItem(Name = "--web3signer-api-urls")]
    [Obsolete("Use Web3signerUrls instead.")]
    public string? Web3signerApiUrls { get; set; }

    [ConfigItem(Description = "List of Web3Signer URLs")]
    [GrandineConfigItem(Name = "--web3signer-urls")]
    public string? Web3signerUrls { get; set; }

    [ConfigItem(Description = "Use validator key cache for faster startup", DefaultValue = "false")]
    [GrandineConfigItem(Name = "--use-validator-key-cache")]
    public bool UseValidatorKeyCache { get; set; }

    [ConfigItem(Description = "Number of epochs to keep slashing protection data for", DefaultValue = "256")]
    [GrandineConfigItem(Name = "--slashing-protection-history-limit")]
    public string? SlashingProtectionHistoryLimit { get; set; }

    [ConfigItem(Description = "Enable validator API", DefaultValue = "false")]
    [GrandineConfigItem(Name = "--enable-validator-api")]
    public bool EnableValidatorApi { get; set; }

    [ConfigItem(Description = "Validator API address", DefaultValue = "127.0.0.1")]
    [GrandineConfigItem(Name = "--validator-api-address")]
    public string? ValidatorApiAddress { get; set; }

    [ConfigItem(Description = "Listen port for validator API", DefaultValue = "5055")]
    [GrandineConfigItem(Name = "--validator-api-port")]
    public string? ValidatorApiPort { get; set; }

    [ConfigItem(Description = "List of Access-Control-Allow-Origin header values for the validator API server. Defaults to the listening URL of the validator API server")]
    [GrandineConfigItem(Name = "--validator-api-allowed-origins")]
    public string? ValidatorApiAllowedOrigins { get; set; }

    [ConfigItem(Description = "Validator API timeout in milliseconds", DefaultValue = "10000")]
    [GrandineConfigItem(Name = "--validator-api-timeout")]
    public string? ValidatorApiTimeout { get; set; }

    [ConfigItem(Description = "Path to a file containing validator API auth token")]
    [GrandineConfigItem(Name = "--validator-api-token-file")]
    public string? ValidatorApiTokenFile { get; set; }

    [ConfigItem(DefaultValue = "Grandine/1.1.1-84a77b3")]
    [GrandineConfigItem(Name = "--graffiti")]
    public string? Graffiti { get; set; }

    [ConfigItem(Description = "List of optional runtime features to enable")]
    [GrandineConfigItem(Name = "--features")]
    public string? Features { get; set; }
}