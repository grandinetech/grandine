// SPDX-FileCopyrightText: 2024 Demerzel Solutions Limited
// SPDX-License-Identifier: LGPL-3.0-only

using System.Collections.Generic;

namespace Grandine.Bindings;

public class GrandineConfig : IGrandineConfig
{
    public bool Enabled { get; set; }

    public string? Network { get; set; }

    public string? ConfigurationFile { get; set; }

    public string? ConfigurationDirectory { get; set; }

    public string? VerifyPhase0PresetFile { get; set; }

    public string? VerifyAltairPresetFile { get; set; }

    public string? VerifyBellatrixPresetFile { get; set; }

    public string? VerifyCapellaPresetFile { get; set; }

    public string? VerifyDenebPresetFile { get; set; }

    public string? VerifyElectraPresetFile { get; set; }

    public string? VerifyConfigurationFile { get; set; }

    public string? TerminalTotalDifficultyOverride { get; set; }

    public string? TerminalBlockHashOverride { get; set; }

    public string? TerminalBlockHashActivationEpochOverride { get; set; }

    public string? DepositContractStartingBlock { get; set; }

    public string? GenesisStateFile { get; set; }

    public string? GenesisStateDownloadUrl { get; set; }

    public string? MaxEmptySlots { get; set; }

    public string? MaxEvents { get; set; }

    public string? CheckpointSyncUrl { get; set; }

    public bool? ForceCheckpointSync { get; set; }

    public string[]? Eth1RpcUrls { get; set; }

    public string? DataDir { get; set; }

    public string? StoreDirectory { get; set; }

    public string? NetworkDir { get; set; }

    public string? ArchivalEpochInterval { get; set; }

    public bool? ArchiveStorage { get; set; }

    public bool? PruneStorage { get; set; }

    public string? UnfinalizedStatesInMemory { get; set; }

    public string? DatabaseSize { get; set; }

    public string? Eth1DatabaseSize { get; set; }

    public string? RequestTimeout { get; set; }

    public string? MaxEpochsToRetainStatesInCache { get; set; }

    public string? StateCacheLockTimeout { get; set; }

    public string? StateSlot { get; set; }

    public bool? SubscribeAllSubnets { get; set; }

    public string? SuggestedFeeRecipient { get; set; }

    public string? JwtId { get; set; }

    public string? JwtSecret { get; set; }

    public string? JwtVersion { get; set; }

    public bool? BackSyncDeprecated { get; set; }

    public bool? BackSync { get; set; }

    public bool? Metrics { get; set; }

    public string? MetricsAddress { get; set; }

    public string? MetricsPort { get; set; }

    public string? MetricsUpdateInterval { get; set; }

    public string? RemoteMetricsUrl { get; set; }

    public bool? TrackLiveness { get; set; }

    public bool? DetectDoppelgangers { get; set; }

    public bool? InMemory { get; set; }

    public string? KzgBackend { get; set; }

    public string[]? BlacklistedBlocks { get; set; }

    public string? HttpAddress { get; set; }

    public string? HttpPort { get; set; }

    public string[]? HttpAllowedOrigins { get; set; }

    public string? Timeout { get; set; }

    public string? ListenAddress { get; set; }

    public string? ListenAddressIpv6 { get; set; }

    public string? Libp2pPort { get; set; }

    public string? Libp2pPortIpv6 { get; set; }

    public bool? DisableQuic { get; set; }

    public bool? DisablePeerScoring { get; set; }

    public bool? DisableUpnp { get; set; }

    public bool? DisableEnrAutoUpdate { get; set; }

    public string? DiscoveryPort { get; set; }

    public string? DiscoveryPortIpv6 { get; set; }

    public string? QuicPort { get; set; }

    public string? QuicPortIpv6 { get; set; }

    public bool? EnablePrivateDiscovery { get; set; }

    public string? EnrAddress { get; set; }

    public string? EnrAddressIpv6 { get; set; }

    public string? EnrTcpPort { get; set; }

    public string? EnrTcpPortIpv6 { get; set; }

    public string? EnrUdpPort { get; set; }

    public string? EnrUdpPortIpv6 { get; set; }

    public string? EnrQuicPort { get; set; }

    public string? EnrQuicPortIpv6 { get; set; }

    public string[]? BootNodes { get; set; }

    public string[]? Libp2pNodes { get; set; }

    public string? Libp2pPrivateKeyFile { get; set; }

    public string? TargetPeers { get; set; }

    public string? TargetSubnetPeers { get; set; }

    public string[]? TrustedPeers { get; set; }

    public string? KeystoreDir { get; set; }

    public string? KeystorePasswordDir { get; set; }

    public string? KeystorePasswordFile { get; set; }

    public string? KeystoreStoragePasswordFile { get; set; }

    public string? BuilderFormat { get; set; }

    public string? BuilderApiUrl { get; set; }

    public string? BuilderUrl { get; set; }

    public bool? BuilderDisableChecks { get; set; }

    public string? BuilderMaxSkippedSlots { get; set; }

    public string? BuilderMaxSkippedSlotsPerEpoch { get; set; }

    public string? DefaultGasLimit { get; set; }

    public string[]? Web3signerPublicKeys { get; set; }

    public bool? Web3signerRefreshKeysEveryEpoch { get; set; }

    public string[]? Web3signerApiUrls { get; set; }

    public string[]? Web3signerUrls { get; set; }

    public bool? UseValidatorKeyCache { get; set; }

    public string? SlashingProtectionHistoryLimit { get; set; }

    public bool? EnableValidatorApi { get; set; }

    public string? ValidatorApiAddress { get; set; }

    public string? ValidatorApiPort { get; set; }

    public string[]? ValidatorApiAllowedOrigins { get; set; }

    public string? ValidatorApiTimeout { get; set; }

    public string? ValidatorApiTokenFile { get; set; }

    public string? Graffiti { get; set; }

    public string[]? Features { get; set; }
}
