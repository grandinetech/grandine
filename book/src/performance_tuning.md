# Performance and memory tuning

Grandine is designed to run well with its defaults. Most operators never need this page. Read it if
memory use is higher than you expect, if you run on small hardware, or if the network stops
finalizing.

## How Grandine uses memory

Grandine keeps fork choice in memory. Everything after the last finalized checkpoint (unfinalized
blocks and the beacon states after them) lives in RAM, and finalized data goes to the database on
disk. In a healthy network finality is about two epochs behind the head, so the in-memory part is
small and stable.

The main consumers of memory are:

- **Unfinalized states.** Grandine keeps the post-state of recent unfinalized blocks in memory, so
  it can process new blocks and attestations without rebuilding states. States more than
  `--unfinalized-states-in-memory` slots behind the head are unloaded. States at epoch boundaries
  are written to the database first, so they can be loaded back if needed.
- **The state cache.** States computed for other reasons (for example the state at a given slot for
  the API or for attestation validation) are cached. States older than
  `--max-epochs-to-retain-states-in-cache` epochs behind the head, or older than the finalized
  slot, are pruned once per epoch.
- **Checkpoint states** for unfinalized checkpoints, dropped as finality advances.
- **Operation pools** (attestations, sync committee messages and others), the pubkey cache, and
  network buffers.

Beacon states share most of their data with each other through persistent data structures, so one
more state in memory costs much less than a full copy.

Grandine needs about 5 GB of memory on a healthy Mainnet. Actual use depends on the
network, the number of validators, the options and the version, so measure it on your own node.

## Measuring memory correctly

Tools like `top` and `ps` show the resident set size (RSS), which includes memory the allocator
holds but the application is not using, and pages the kernel has not reclaimed yet. On a machine
with plenty of free RAM, RSS overstates what Grandine needs.

To see how much memory Grandine really needs, put the system under memory pressure so the kernel
reclaims what it can. The [`stress-ng`](https://github.com/ColinIanKing/stress-ng) tool can do that
by allocating 90% of the available memory:

```bash
stress-ng --vm-bytes $(awk '/MemAvailable/{printf "%d\n", $2 * 0.9;}' < /proc/meminfo)k --vm-keep -m 1
```

Watch Grandine's RSS while it runs, then stop it with Ctrl+C.

> **Warning:** Do this on a test machine, or at a time when a short slowdown is acceptable. Memory
> pressure can make every process on the host slow, including the execution client, and the
> kernel's out-of-memory killer can end processes if you overshoot.

Over time, the [metrics](./metrics.md) give a better picture:

- `GRANDINE_USED_MEMORY`: the process's memory as reported by the OS.
- `JEMALLOC_BYTES_ALLOCATED`: bytes the application has allocated and not freed.
- `JEMALLOC_BYTES_RESIDENT` and `JEMALLOC_BYTES_RETAINED`: memory the allocator holds from the OS.

If `JEMALLOC_BYTES_ALLOCATED` is stable while RSS is higher, the difference is allocator overhead
and memory not yet returned to the OS, not a leak. The **Overview** Grafana dashboard plots these.

## The allocator

Grandine uses [jemalloc](https://jemalloc.net/) (through `tikv-jemallocator`) as its global
allocator on every platform except Windows with the MSVC toolchain, which uses the system
allocator. jemalloc reduces fragmentation in a long-running, multi-threaded process like a beacon
node.

Grandine builds jemalloc with prefixed symbols, so it reads tuning options from the
`_RJEM_MALLOC_CONF` environment variable, not `MALLOC_CONF`. The defaults suit most operators.

## Memory options

### `--unfinalized-states-in-memory`

How many slots of unfinalized states to keep in memory behind the head. Default: `128` (four epochs
on mainnet). The minimum is two epochs, `64` slots on mainnet; lower values are refused with
`--unfinalized-states-in-memory must be at least 64`.

- Lower it toward `64` to save memory, at the cost of more state loading and recomputation when
  older states are needed, for example during reorgs or for late attestations.
- Raise it if you have spare RAM and see recomputation slowing the node down.

```bash
grandine --network mainnet --unfinalized-states-in-memory 64 ...
```

### `--max-epochs-to-retain-states-in-cache`

How many epochs behind the head the state cache keeps states. Default: `8`. A lower value saves
memory when the cache holds many states, for example on a node that serves many API requests for
recent states. The cache never keeps states older than the finalized slot, whatever this value is.

### `--state-cache-lock-timeout`

How long, in milliseconds, a task waits for the lock on a state cache entry before it gives up and
computes the state itself. Default: `1500`. You should not need to change it.

### `--max-empty-slots`

How many empty slots Grandine is willing to process on top of a state. Default: `32`. If the chain
has a longer run of slots without blocks, for example after a network outage, building a state
fails with `too many empty slots after state`, and validators stop performing duties on a head that
far behind. Raise it only in such an exceptional situation.

### `--database-size`

The maximum size of the beacon database. Default: 1 TiB. This is an upper limit for the memory
mapping, not space that is allocated in advance. If the database reaches the limit, Grandine
restarts its runtime with a doubled limit and logs `increasing environment map size limits`.
See [Storage and database](./storage.md).

## CPU and thread pools

Grandine parallelizes most work. You do not configure thread counts; Grandine sizes its pools from
the number of CPUs it sees (`nproc`):

- **Fork choice thread pool.** One worker per CPU runs fork choice tasks: block processing,
  attestation and aggregate validation, blob and data column sidecar handling, and state
  preprocessing. Tasks are prioritized: blocks, blob sidecars and checkpoint states first, then data column sidecars, then attestations, aggregates and background persistence.
- **Attestation verification** verifies signatures in batches, which is much cheaper than one at a
  time.
- **Dedicated executors** run CPU-heavy jobs away from the async runtime that handles networking
  and APIs:
  - `de-normal`: one thread per CPU, normal priority, for block production and similar work.
  - `de-low`: a quarter of the CPUs (at least one), at the lowest scheduling priority (nice 19),
    for background work.
  - `de-recover` (a quarter of the CPUs) and `de-reconstruct` (one thread), both at nice 19, for
    data column recovery and reconstruction.
- **Rayon** for data-parallel loops.

Thread names appear in `top -H` and in panics, which helps when you investigate CPU use. The
dedicated executor task counts and timings are on the **Overview** dashboard.

To limit how many CPUs Grandine uses, restrict the process instead of looking for a flag, for
example with `taskset`, the systemd `CPUAffinity=` setting, or Docker's `--cpuset-cpus`. Pools are
sized from the CPUs available to the process. A cgroup CPU quota, such as Docker's `--cpus` or the
systemd `CPUQuota=` setting, also counts: the pools use the quota rounded up to whole CPUs, or the
affinity count if that is lower.

Other options that affect CPU use:

- `--subscribe-all-subnets` and `--supernode` make the node process far more gossip. Use them only
  when you need them. See [Networking and peers](./networking.md) and
  [PeerDAS and blob data](./peerdas.md).
- `--use-validator-key-cache` speeds up startup with many local keystores. Keystore decryption is
  deliberately slow; the cache stores the keys in a single encrypted file in the validator
  directory, which is faster to load. See [Managing validator keys](./key_management.md).

## Disk

Grandine writes finalized data in batches and reads states from disk when it needs them. A fast
SSD (NVMe preferred) matters more than raw capacity. Archive nodes (`--archive-storage`) and
back-sync write much more. See [System requirements](./hardware_requirements.md) and
[Storage and database](./storage.md).

## Long periods of non-finality

When the network stops finalizing, nothing becomes finalized, so the unfinalized part of fork choice
keeps growing. With an in-memory fork choice, that shows up as rising memory use, and more state
writes as Grandine persists the epoch boundary states it unloads.

If this happens:

1. **Stay on the latest release.** Client teams often ship fixes during incidents. Watch the
   Grandine Discord and the release page. See [Updating Grandine](./updating.md).
2. **Watch memory and disk.** Track `GRANDINE_USED_MEMORY`, `SYSTEM_USED_MEMORY` and free disk space,
   and alert before they run out.
3. **Lower the in-memory limits** if memory gets tight:

   ```bash
   grandine --network mainnet \
     --unfinalized-states-in-memory 64 \
     --max-epochs-to-retain-states-in-cache 2 \
     ...
   ```

   Lower values trade memory for CPU and disk reads, as states are reloaded or recomputed more often.
4. **Add swap or RAM** as a last resort, so the out-of-memory killer does not stop the node.
5. **Do not resync from a checkpoint during non-finality** unless you have to. A checkpoint sync
   starts from the last finalized state, which may be far behind, and the node then has to process
   every unfinalized block again.
6. **Keep validators running.** Validators that keep attesting help the network finalize again, and
   inactivity penalties grow while it does not.

## Quick checklist

- Memory looks high: measure it under memory pressure (above) before you change anything.
- Small machine: `--unfinalized-states-in-memory 64` and `--max-epochs-to-retain-states-in-cache 4`.
- CPU spikes: enable the `WarnOnFailedServiceHealthChecks` and `WarnOnStateCacheSlotProcessing`
  [runtime features](./runtime_features.md) to find the cause, and include the logs in a report.
- Slow startup with many keys: `--use-validator-key-cache`.

## Command line options

See [Command line reference](./cli_options.md) for the full list.

- `--unfinalized-states-in-memory`: default `128`. Slots of unfinalized states kept in memory behind the head. Minimum: two epochs.
- `--max-epochs-to-retain-states-in-cache`: default `8`. Epochs behind the head that the state cache keeps states for.
- `--state-cache-lock-timeout`: default `1500`. State cache lock timeout in milliseconds.
- `--max-empty-slots`: default `32`. Maximum number of empty slots processed on top of a state.
- `--database-size`: default `1 TiB`. Maximum size of the beacon database.
- `--use-validator-key-cache`: default disabled. Cache validator keys in an encrypted file for faster startup.
- `--in-memory`: default disabled. Keep all data in memory and nothing on disk. For testing only.
