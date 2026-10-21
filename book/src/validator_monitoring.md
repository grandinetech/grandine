# Monitoring validator performance

A healthy validator attests in every epoch, proposes when chosen, and takes part in sync committees
when selected. This page shows how to confirm that, using Grandine's logs, its performance reports,
its Prometheus metrics, the Beacon Node API and an external explorer. It ends with a checklist.

For setting up Prometheus and Grafana in general, see [Metrics](./metrics.md). For log levels and
formats, see [Logging](./logging.md).

## Duty log lines

Grandine logs each duty at the `info` level. With validators attached, you should see lines like
these every slot or epoch:

```text
loaded 4 validator key(s)
validators [4242, 4243] attesting in slot 123456
validators [4242] aggregating in slot 123456
validators [4243] participating in sync subcommittee 2 in slot 123457
validators [4243] aggregating in sync committee in slot 123457
starting block proposal task for validator 4242 at slot 123460
validator 4242 proposing beacon block with root 0x... in slot 123460
```

- `loaded N validator key(s)` appears once at startup. If you expected keys and see
  `failed to load validator keys` instead, check the keystore and password options.
- `attesting in slot` lists the validator indices that attested in that slot. Each active validator
  should appear once per epoch.
- A proposal ends with `proposing beacon block with root ...`. With a builder it says
  `using the builder API` (before Gloas) or `using builder N` (from Gloas on).

Warnings to look for:

| Log message | Meaning |
| --- | --- |
| `validator client cannot perform duties: beacon node is syncing ...` | The built-in beacon node is not synced yet. Duties are skipped. |
| `validator client cannot perform duties: beacon node is out of sync ...` | The head is too far behind the clock. Check peers and the execution client. |
| `validator cannot perform its duties because chain head has not been fully verified by an execution engine` | The head is optimistic: the execution client is syncing or unreachable. |
| `no beacon node given with --beacon-node-urls reported a head recent enough to perform duties for slot N` | `grandine vc` only: none of its beacon nodes is usable. |
| `validator N skipping beacon block proposal in slot S: ...` | Block production failed. The message gives the reason. |
| `failed to publish attestations: ...` | The attestation could not be sent to the network or beacon node. |
| `Validator 0x... skipping attesting duty in slot S since not enough time has passed ...` | [Doppelganger protection](./doppelganger_protection.md) is still waiting. Expected after a start. |
| `slashing protector rejected slashable attestation ...` | [Slashing protection](./slashing_protection.md) refused to sign. Investigate if it repeats. |

## Performance reports

With the built-in beacon node, Grandine can print a summary of how its validators did. Start it with
`--report-validator-performance`:

```bash
grandine                                  \
  --network mainnet                       \
  --jwt-secret /path/to/jwt.hex           \
  --eth1-rpc-urls http://EL-HOST:8551     \
  --keystore-dir /path/to/validator_keys  \
  --keystore-password-file /path/to/password.txt \
  --report-validator-performance
```

Once per epoch, while the node is synced, it logs:

```text
attestation performance for epoch: 1000, expected: 4, produced: 4, correct target: 4 (100.00%), correct head: 4 (100.00%), included: 4 (100.00%), inclusion delays: ...
sync committee message performance for epoch: 1001, expected: 32, produced: 32, correct: 32, included: 32 (100.00%)
```

- The attestation report covers the epoch before the previous one, because attestations can still
  be included one epoch later.
- `expected` is the number of validators with an attestation duty, `produced` the number of
  attestations seen, and `included` the number found in blocks.
- `correct target` and `correct head` show how many votes matched the canonical chain. A low head
  rate often means late blocks or a slow node.
- `inclusion delays` summarizes how many slots it took for attestations to be included. A delay of 1
  is ideal.

The report also warns about individual votes, for example:

```text
validators [4242] voted for outdated head 0x... (by 2 slots) at slot 123456 (expected to vote for block 0x...)
validators [4242] voted for non-canonical block 0x... at slot 123456 (expected to vote for block 0x...)
```

If no validator is in a sync committee, the sync report says
`no sync committee members for epoch N with M registered validators`.

> **Note:** `--report-validator-performance` reads blocks from the built-in beacon node. It is not
> accepted with `grandine bn`, and `grandine vc` refuses it with
> `--report-validator-performance reads blocks from the built-in beacon node`. With a separate
> validator client, use an explorer or the Beacon Node API instead.

## Prometheus metrics

Enable metrics with `--metrics`. Grandine serves them at `http://127.0.0.1:5054/metrics` by default.
Change the address and port with `--metrics-address` and `--metrics-port`.

```bash
grandine ... --metrics
curl -s http://127.0.0.1:5054/metrics | grep -i validator
```

A minimal Prometheus scrape configuration:

```yaml
scrape_configs:
  - job_name: grandine
    static_configs:
      - targets: ["127.0.0.1:5054"]
```

Validator metrics (also exported by a separate `grandine vc`):

| Metric | Type | Meaning |
| --- | --- | --- |
| `VALIDATOR_PROPOSE_SUCCESSES` | counter | Block proposals that succeeded. |
| `VALIDATOR_PROPOSE_TIMES` | histogram | Time to produce a block. |
| `VALIDATOR_ATTEST_TIMES` | histogram | Time to perform an attestation duty. |
| `VALIDATOR_PROPOSE_TICK_TIMES`, `VALIDATOR_ATTEST_TICK_TIMES`, `VALIDATOR_AGGREGATE_TICK_TIMES` | histogram | Time spent handling each part of the slot. |
| `VALIDATOR_EPOCH_PROCESSING_TIMES` | histogram | Time spent on per-epoch validator work. |
| `VALIDATOR_ATTEST_SLASHING_PROTECTOR_TIMES`, `VALIDATOR_PROPOSAL_SLASHING_PROTECTOR_TIMES` | histogram | Time spent in slashing protection checks. |
| `WEB3SIGNER_SIGN_TIMES`, `WEB3SIGNER_LOAD_KEYS_TIMES` | histogram | Web3Signer request times. |
| `VALIDATOR_API_RESPONSE_TIMES` | histogram | Validator (Keymanager) API response times. |
| `beacon_clock_slot` | gauge | Current slot according to the clock. |

Beacon node metrics that matter for validators (not exported by `grandine vc`):

| Metric | Meaning |
| --- | --- |
| `beacon_head_slot` | Slot of the current head. Should follow `beacon_clock_slot` closely. |
| `beacon_finalized_epoch` | Latest finalized epoch. Should advance every epoch. |
| `libp2p_peers` | Number of connected peers. |
| `beacon_participation_prev_epoch_target_attesting_gwei_total` and `beacon_participation_prev_epoch_active_gwei_total` | Network-wide participation in the previous epoch. |
| `BUILDER_GET_EXECUTION_PAYLOAD_HEADER_TIMES`, `BUILDER_REGISTER_VALIDATORS_TIMES` | Builder request times, with a [builder](./builder_api_and_mev.md). |

Histograms appear with `_bucket`, `_sum` and `_count` suffixes. For example, a Prometheus alert on a
stalled head:

```yaml
- alert: GrandineHeadStalled
  expr: beacon_clock_slot - beacon_head_slot > 4
  for: 5m
```

Grandine does not export per-validator balances or effectiveness metrics. Use an explorer or the
Beacon Node API for those.

## Beacon Node API

The [Beacon Node API](./beacon_node_api.md) (`127.0.0.1:5052` by default) answers most "is it
working?" questions directly:

```bash
# Sync status: is_syncing should be false, is_optimistic false, el_offline false
curl -s http://127.0.0.1:5052/eth/v1/node/syncing

# Peer count
curl -s http://127.0.0.1:5052/eth/v1/node/peer_count

# Validator status and balance (by public key or index)
curl -s http://127.0.0.1:5052/eth/v1/beacon/states/head/validators/0xPUBKEY

# Upcoming proposals in the current epoch
curl -s http://127.0.0.1:5052/eth/v1/validator/duties/proposer/EPOCH
```

A rising balance from one epoch to the next means the validator earns rewards.

### Liveness tracking

With `--track-liveness`, the beacon node records which validators it has seen attesting or
proposing in the current and the previous epoch, and serves the standard liveness endpoint:

```bash
curl -s -X POST -H "Content-Type: application/json" \
  -d '["4242", "4243"]' \
  http://127.0.0.1:5052/eth/v1/validator/liveness/EPOCH
```

Only the current and the previous epoch can be queried. `is_live: true` means the validator was seen
on the network. Liveness tracking is also what [doppelganger
protection](./doppelganger_protection.md) uses. Without `--track-liveness`, a Grandine beacon node
returns an error for this endpoint.

## beaconcha.in and other explorers

Block explorers such as [beaconcha.in](https://beaconcha.in) show each validator's attestations,
proposals, sync committee duties and rewards, and can send alerts by email or through their mobile
app. Look up your validators by public key or index.

Grandine can also push its own status to beaconcha.in's
[machine metrics](https://docs.beaconcha.in/api/machine-metrics-overview) once a minute. Create an
API key at [beaconcha.in/api/key-management](https://beaconcha.in/api/key-management), then pass the
endpoint with your key, and optionally a machine name, to `--remote-metrics-url`:

```bash
grandine ... --remote-metrics-url "https://beaconcha.in/api/v1/client/metrics?apikey=YOUR_API_KEY&machine=MACHINE_NAME"
```

Grandine sends beacon node, validator (number of active and total validators) and system metrics.
The beaconcha.in mobile app then shows the machine and can alert you when it goes offline. See
[Metrics](./metrics.md).

## Is everything fine? A checklist

Run through this list after setting up, after every upgrade, and whenever something looks wrong.

1. **Version.** The startup log line `client version: ...` shows the release you expect.
2. **Execution client.** It is synced, and Grandine reaches it. `GET /eth/v1/node/syncing` reports
   `el_offline: false`. See [Connecting an execution client](./execution_client.md).
3. **Beacon node synced.** `is_syncing: false` and `is_optimistic: false`, and `beacon_head_slot`
   stays within a slot or two of `beacon_clock_slot`.
4. **Peers.** The peer count is stable and near the target (`--target-peers`). See
   [Networking and peers](./networking.md).
5. **Finality.** `beacon_finalized_epoch` advances every epoch, and the log shows
   `new finalized checkpoint` regularly.
6. **Keys loaded.** The log shows `loaded N validator key(s)` with the expected N, and no
   `failed to load validator keys`.
7. **Fee recipient.** The startup line `suggested fee recipient: 0x...` shows your address, not the
   Grandine donation address. See [Fee recipient, graffiti and gas limit](./fee_recipient.md).
8. **Validators active.** Their status is `active_ongoing` in the Beacon Node API or on an explorer.
9. **Attesting.** Each validator index appears in a `validators [...] attesting in slot` line once
   per epoch. With `--report-validator-performance`, `included` and `correct target` are close to
   100%.
10. **No warnings.** No repeated `cannot perform duties`, `slashing protector rejected` or
    `failed to publish` messages.
11. **Balances.** Balances rise from epoch to epoch on an explorer.
12. **Slashing protection backed up.** You have a recent export. See
    [Slashing protection](./slashing_protection.md).
13. **Monitoring and alerts.** Prometheus scrapes the metrics endpoint, or beaconcha.in monitoring
    is set up, and alerts reach you.
14. **Service.** Grandine runs as a service that restarts after a reboot. See
    [Running as a service](./running_as_a_service.md).

Some missed attestations are normal: late blocks, reorgs and restarts all cause them. A validator
that misses most of its attestations for several epochs needs attention. See
[Troubleshooting](./troubleshooting.md).

## Command line options

- `--metrics` (default: disabled): serve Prometheus metrics.
- `--metrics-address` (default: `127.0.0.1`): address of the metrics endpoint.
- `--metrics-port` (default: `5054`): port of the metrics endpoint.
- `--remote-metrics-url` (default: none): URL to push metrics to once a minute, for example
  beaconcha.in.
- `--report-validator-performance` (default: disabled): log attestation and sync committee
  performance once per epoch. Requires the built-in beacon node.
- `--track-liveness` (default: disabled): beacon node option. Record validator liveness and serve
  `POST /eth/v1/validator/liveness/{epoch}`.

See the [command line reference](./cli_options.md) for the full list.
