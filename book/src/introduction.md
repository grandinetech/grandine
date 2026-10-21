# Introduction

<div class="hero">
<p class="tagline">A fast, lightweight Ethereum consensus client</p>
<p class="subline">Highly optimized, parallel by design and written in Rust. Run a beacon node, a
validator client, or both, from a single binary.</p>
<div class="actions">
<a class="button primary" href="quick_start.html">Quick start</a>
<a class="button" href="downloads.html">Download</a>
<a class="button" href="https://github.com/grandinetech/grandine">GitHub</a>
</div>
</div>

## What makes Grandine different

<div class="features">
<a class="feature" href="#performance">
<span class="title">Parallel by design</span>
<span class="line">A highly optimized state transition function, with every CPU core at work.</span>
</a>
<a class="feature" href="performance_tuning.html">
<span class="title">Light on memory</span>
<span class="line">About 5 GB on a healthy Mainnet, thanks to structural sharing.</span>
</a>
<a class="feature" href="historical_data.html">
<span class="title">Archive node <span class="badge">coming soon</span></span>
<span class="line">The best historical data serving performance among consensus clients.</span>
</a>
<a class="feature" href="nethermind_integration.html">
<span class="title">Embedded in Nethermind</span>
<span class="line">Native Engine API calls with no HTTP or JSON, for the highest performance.</span>
</a>
<a class="feature" href="validator_client.html">
<span class="title">One binary, three modes</span>
<span class="line">Beacon node, validator client, or both together.</span>
</a>
<a class="feature" href="https://github.com/grandinetech/grandine/tree/develop/audit">
<span class="title">Audited</span>
<span class="line">Reviewed by Matter Labs and X41 D-Sec, and tested by Antithesis.</span>
</a>
</div>

> **Note:** No audit makes software risk free. Protect validator keys with the approach you trust,
> for example a remote signer such as [Web3Signer](./web3signer.md).

## Performance

Grandine was built from the start for speed: a highly optimized state transition function, and every
CPU core put to work.

<!-- TODO(verify): add current measured figures (for example blocks per second during sync, block
import time, CPU use per validator count) and the hardware they were measured on. No current
measurement is published. The only third-party one, MigaLabs (arXiv:2311.05252, cited in README.md),
measured Grandine 0.2.0 in March 2022 before the Merge and is too old to quote. -->

The speed comes from optimizations at every layer:

- **An optimized state transition function.** The state transition function applies each block and
  epoch to the beacon state, and it is the hottest code path in a consensus client. Grandine
  optimizes it with micro-optimizations throughout and with parallelism.
- **Parallel verification.** Signatures are verified in batches, and blocks, attestations,
  aggregates, blob sidecars and data columns are validated in parallel.
- **A lock-free fork choice.** A single thread applies verified results to the fork choice store,
  while the Beacon API and the validator client read recent snapshots. Readers never wait for the
  writer, and the writer never waits for them.
- **No state copies.** Beacon states use structural sharing: a new state shares every unchanged part
  with its parent instead of copying it. Block processing avoids the cost of cloning full states, and
  hundreds of unfinalized states cost little more memory than one.
- **Heavy work kept off the network path.** Block production, data column recovery and other
  CPU-heavy jobs run on dedicated executors, separate from the async runtime that serves peers and
  APIs.

[How Grandine works](./architecture.md) and
[Performance and memory tuning](./performance_tuning.md) explain these mechanisms in more detail.

## About Grandine

Grandine is an Ethereum consensus client written in Rust. It follows the beacon chain, takes part in
consensus through its standalone or built-in validator client, and serves the standard Beacon Node API. Grandine is
built by the [Grandine core team](https://grandine.io/) and is open source under the GNU General
Public License, version 3. The source is on [GitHub](https://github.com/grandinetech/grandine).

This book is for node operators: home stakers, staking providers, infrastructure teams and anyone who
wants to run a beacon node. It explains how to install Grandine, connect it to an execution client,
run validators safely and keep the node healthy.

## Supported networks

Grandine connects to Ethereum Mainnet and to the Sepolia and Hoodi testnets out of the box. It still
accepts Holesky, which has reached its end of life.
It can also join devnets and other custom networks from a configuration directory. See
[Supported networks](./networks.md).

## How to use this book

If you are new to Grandine, read the pages in this order:

1. [System requirements](./hardware_requirements.md): check that your machine is big enough.
2. [How Grandine works](./architecture.md): the beacon node, validator client and execution client,
   and how they fit together.
3. [Installation overview](./installation.md): pick a binary, a Docker image or a source build.
4. [Quick start](./quick_start.md): run an execution client and Grandine on the Hoodi testnet.
5. [Running as a service](./running_as_a_service.md): run Grandine under systemd or Docker Compose.
6. [Becoming a validator](./validator_overview.md): add validator keys once the node is synced.

> **Tip:** Practice on the Hoodi testnet before you run validators on Mainnet. Testnet ether has no
> value, so mistakes there cost nothing.

Later sections cover the beacon node in depth ([Running a beacon node](./beacon_node.md),
[Checkpoint sync](./checkpoint_sync.md), [Storage and database](./storage.md)), validator
operations ([Validator client](./validator_client.md), [Slashing protection](./slashing_protection.md)),
the APIs ([Beacon Node API](./beacon_node_api.md)), monitoring ([Metrics](./metrics.md),
[Logging](./logging.md)) and reference material ([Command line reference](./cli_options.md),
[Troubleshooting](./troubleshooting.md), [FAQ](./faq.md)).

## Getting help

The fastest way to reach the team and other operators is the
[Grandine Discord](https://discord.gg/H9XCdUSyZd).
Report bugs on [GitHub](https://github.com/grandinetech/grandine/issues). See [Support](./support.md).
