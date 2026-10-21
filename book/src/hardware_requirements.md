# System requirements

This page lists what Grandine itself needs. A staking node also runs an execution client (EL) such as
Geth or Nethermind on the same machine, and the execution client needs much more memory and disk than
Grandine. Add its requirements to the figures below. See [Sizing a full node](#sizing-a-full-node).

## Grandine requirements

These figures are estimates for Grandine on Mainnet, with the built-in validator client and the
default storage mode. They include headroom for the operating system and for periods without
finality, but are not yet backed by published measurements.

| Resource | Minimum | Recommended |
| --- | --- | --- |
| CPU | 2 cores, x86-64 or ARM64 | 4 cores or more |
| Memory (RAM) | 8 GB | 16 GB |
| Disk | SATA SSD, see [Disk usage by storage mode](#disk-usage-by-storage-mode) | NVMe SSD |
| Network | 10 Mbit/s, no data cap | 25 Mbit/s or faster, no data cap |
| Operating system | 64-bit Linux, macOS or Windows | 64-bit Linux |
| Time | Clock synchronized with NTP | Clock synchronized with NTP |

<!-- TODO(verify): the minimum and recommended CPU, memory and network figures are placeholders until the Grandine team confirms them; no published measurement exists. Memory: about 5 GB on a healthy Mainnet, confirmed by the team; README.md's 2.5 GB is outdated. The memory figures add headroom for the operating system and for periods without finality. -->

See [Operating systems and architectures](#operating-systems-and-architectures) for the supported
platforms.

Testnets such as Hoodi need less disk than Mainnet.
<!-- TODO(verify): needs a measured Hoodi database size and memory use. Hoodi uses the same retention windows as Mainnet (types/src/config.rs), so "less disk" depends on its chain and validator set being smaller; confirm. -->

### CPU

Grandine spreads its work across all CPU cores. More cores help most during the initial sync, when the
node runs many validators, and when it subscribes to many subnets.

The official binaries use the portable build of the `blst` BLS library, so they also run on older
x86-64 CPUs that lack the ADX instruction set extension.

### Memory

On a healthy Mainnet, Grandine needs about **5 GB** of memory. Grandine keeps the unfinalized part of
the chain in memory, so memory use grows during a long period without finality. To measure how much
memory Grandine really uses, and to limit it during non-finality, see
[Performance and memory tuning](./performance_tuning.md).

### Disk usage by storage mode

Use an SSD, preferably NVMe. Grandine stores the finalized chain in an embedded `libmdbx` database, and
how much it stores depends on the storage mode:

| Storage mode | Option | What is stored | Approximate Mainnet size |
| --- | --- | --- | --- |
| Prune | `--prune-storage` | A single finalized checkpoint state and its block. Not for production use: it does not keep blocks and blob data for the period the specification requires | <!-- TODO(verify): needs a measured Mainnet database size in prune mode --> A few GB |
| Standard (default) | none | Finalized blocks of the last 33,024 epochs (about 147 days, roughly five months) and a state every 32 epochs (`--archival-epoch-interval`) over the same period, plus blob data of the last 4,096 epochs (about 18 days) | <!-- TODO(verify): needs a measured steady-state Mainnet database size --> Grows until the retention window of about five months is filled, then stays roughly steady |
| Archive | `--archive-storage` | All blocks, optimised state storage and all blob data, back to genesis with `--back-sync` | <!-- TODO(verify): needs a measured Mainnet archive database size --> Several hundred GB or more |

The retention windows come from the consensus specification and are the same on Mainnet and Hoodi.
After the Gloas fork, the block window shrinks to 14,299 epochs (about 64 days).

> **Note:** A new high-performance archive node is coming soon. See
> [Back-sync and archive nodes](./historical_data.md).

### Network

A beacon node keeps many peer connections and exchanges data with them continuously. Use a reliable
connection without a monthly data cap, and open the peer-to-peer ports in your firewall:

- 9000 TCP and UDP, and 9001 UDP (QUIC), over IPv4
- 9050 TCP and UDP, and 9051 UDP (QUIC), over IPv6. These are used only when IPv6 is enabled with
  `--listen-address-ipv6`

See [Networking and peers](./networking.md) and [Default ports and paths](./default_ports.md).

### Time synchronization

Every duty in Ethereum is tied to a slot, so the system clock must be accurate. Run a time
synchronization service such as `chrony` or `systemd-timesyncd`. A clock that drifts by even a second
or two causes missed attestations, and peers reject messages from nodes whose clocks are far off.

## When you need more

Some setups need more resources than the figures above:

- **Many validators.** A single Grandine node can run up to tens of thousands of validators. CPU use
  and network traffic grow with the number of validators, because the node subscribes to more
  attestation subnets and produces more messages.
  <!-- TODO(verify): needs CPU and memory measurements per number of validators. The only sourced figure is README.md: the team runs 50,000 Holesky validators on one developer machine, without its specifications. -->
- **Supernodes.** A node started with `--supernode` downloads and stores every data column, and
  `--semi-supernode` half of them. Both need noticeably more bandwidth and disk than a regular node.
  See [PeerDAS and blob data](./peerdas.md).
- **Archive nodes.** An archive node needs much more disk, and benefits from a fast NVMe SSD for
  serving historical data. See [Back-sync and archive nodes](./historical_data.md).
- **All subnets.** `--subscribe-all-subnets` increases CPU use and traffic.

## Sizing a full node

To size the machine, add your execution client's requirements to Grandine's. The execution client
usually needs most of the memory and disk. Check its documentation:

- [Geth](https://geth.ethereum.org/docs/getting-started/hardware-requirements)
- [Nethermind](https://docs.nethermind.io/get-started/system-requirements)
- [Besu](https://besu.hyperledger.org/public-networks/get-started/system-requirements)
- [Erigon](https://docs.erigon.tech/get-started/hardware-requirements)
- [Reth](https://reth.rs/run/system-requirements)

As a rough orientation, a Mainnet node that runs Grandine and a typical execution client is
comfortable with:

| Resource | Full node (Grandine + execution client) |
| --- | --- |
| CPU | 4 to 8 cores |
| Memory (RAM) | 32 GB |
| Disk | 2 TB NVMe SSD |
| Network | 25 Mbit/s or faster, no data cap |

<!-- TODO(verify): orientation figures for a full node are not measured; they depend on the execution client. Needs a measured Grandine plus execution client setup on Mainnet. -->

> **Note:** Execution clients now expire old chain history on a rolling basis, so their disk usage
> no longer grows without bound. A 2 TB disk is enough for a full node with a typical execution
> client. Archive nodes need much more.

When Grandine runs [embedded in Nethermind](./nethermind_integration.md), both clients share one
process. Size the machine the same way: Nethermind's requirements plus Grandine's.

For reliability, a stable internet connection and an uninterruptible power supply (UPS) help a
validator stay online.

## Operating systems and architectures

Each [release](https://github.com/grandinetech/grandine/releases) publishes these binaries, where
`VERSION` is the Grandine version:

| OS | Architecture | Binary |
| --- | --- | --- |
| Linux | x86-64 (amd64) | `grandine-VERSION-linux-x64` |
| Linux | ARM64 (aarch64) | `grandine-VERSION-linux-arm64` |
| macOS | Intel x86-64 | `grandine-VERSION-osx-x64` |
| macOS | Apple silicon (ARM64) | `grandine-VERSION-osx-arm64` |
| Windows | x86-64 | `grandine-VERSION-win-x64.exe` |

Each release also publishes [Grandine embedded in Nethermind](./nethermind_integration.md) as one
archive per platform, where `NETHERMIND_VERSION` is the bundled Nethermind version:

| OS | Architecture | Archive |
| --- | --- | --- |
| Linux | x86-64 (amd64) | `grandine-VERSION-nethermind-NETHERMIND_VERSION-linux-x64.zip` |
| Linux | ARM64 (aarch64) | `grandine-VERSION-nethermind-NETHERMIND_VERSION-linux-arm64.zip` |
| macOS | Intel x86-64 | `grandine-VERSION-nethermind-NETHERMIND_VERSION-macos-x64.zip` |
| macOS | Apple silicon (ARM64) | `grandine-VERSION-nethermind-NETHERMIND_VERSION-macos-arm64.zip` |
| Windows | x86-64 | `grandine-VERSION-nethermind-NETHERMIND_VERSION-windows-x64.zip` |

Docker images are published for `linux/amd64` and `linux/arm64`. Linux is the most tested platform and
the one this book assumes. See [Pre-built binaries and Docker](./downloads.md).
