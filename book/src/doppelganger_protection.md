# Doppelganger protection

A doppelganger is a second copy of your validator: the same key, running somewhere else at the same
time. It may be an old machine you forgot to stop, a backup that started on its own, or a failover
script that fired too early. Two copies of a key will sooner or later sign conflicting messages, and
the validator will be slashed. [Slashing protection](./slashing_protection.md) cannot prevent this,
because each copy has its own database.

Doppelganger protection is a safety check at startup. Before Grandine lets a validator sign, it
watches the network for a while to see whether that validator is already active. If it is, Grandine
does not sign anything and shuts down.

## When to use it

Enable it whenever there is any chance that a key runs elsewhere:

- after moving validators from another machine or another client;
- after restoring from a backup;
- in setups with manual or automatic failover.

The cost is a few missed epochs of attestations on every start (see [The cost](#the-cost)). Many
operators keep it on all the time and accept that cost on each restart.

> **Warning:** Doppelganger protection is a last line of defense, not a license to run keys in two
> places. It can only see a duplicate that is online and attesting while the check runs. A duplicate
> that starts later, after the check has passed, is not detected. Never run the same keys in two
> validator clients, even briefly.

## Enabling it

### With the built-in validator client

When Grandine runs the beacon node and the validator client in one process, enable liveness tracking
as well. The built-in beacon node uses it to see which validators are active:

```bash
grandine                                  \
  --network mainnet                       \
  --jwt-secret /path/to/jwt.hex           \
  --eth1-rpc-urls http://EL-HOST:8551     \
  --keystore-dir /path/to/validator_keys  \
  --keystore-password-file /path/to/password.txt \
  --track-liveness                        \
  --detect-doppelgangers
```

Without `--track-liveness`, Grandine refuses to start:

```text
--track-liveness must be specified for --detect-doppelgangers with the built-in beacon node
```

### With a separate validator client

`grandine vc` asks its beacon nodes through the standard liveness endpoint,
`POST /eth/v1/validator/liveness/{epoch}`. It takes no `--track-liveness` option:

```bash
grandine vc                                   \
  --network hoodi                             \
  --beacon-node-urls http://BN-HOST:5052      \
  --keystore-dir /path/to/validator_keys      \
  --keystore-password-file /path/to/password.txt \
  --detect-doppelgangers
```

Every beacon node in `--beacon-node-urls` that the validator client may use must serve that
endpoint. A Grandine beacon node serves it only when started with `--track-liveness`. Without it,
the endpoint returns an error, the check cannot complete, and the validators never start their
duties. The validator client logs:

```text
doppelganger liveness check failed: ...
```

## How it works

1. **Tracking starts.** At startup, every loaded key is put under watch. Keys added later, through
   the [Keymanager API](./keymanager_api.md) or a [Web3Signer](./web3signer.md) refresh, are put
   under watch at the next epoch boundary.
2. **Liveness checks.** Late in every slot, Grandine asks whether any watched validator was seen
   attesting or proposing in the previous or the current epoch. A beacon node with liveness tracking
   records this from attestations and blocks it sees on the network.
3. **Waiting period.** A validator stays under watch for **2 epochs** (64 slots, about 13 minutes on
   mainnet) from the slot its watch started. During that time it performs no duties. Grandine logs:

   ```text
   Validator 0x93...4a skipping attesting duty in slot 123456 since not enough time has passed to ensure there are no doppelganger validators participating on network. Validator will start performing duties on slot 123520.
   ```

4. **Release.** Once the waiting period is over and the latest checks found nothing, the validator
   starts performing its duties normally.

Some details:

- A key whose validator index is not yet known (for example, a deposit that has not been processed)
  cannot be checked. Grandine warns that it "cannot be checked until its index is known; it will not
  perform duties". Its waiting period starts when the index becomes known.
- If a liveness query fails, the release is postponed until a check succeeds. Grandine never
  releases a validator on a failed check.
- At the genesis slot of a new network, there is nothing to watch, so validators start at once.

Besides skipping duties, the signer itself refuses to sign for a watched validator, as a second
safety net:

```text
Doppelganger protection prevented validator 0x93...4a from signing a message since not enough time has passed to ensure there are no duplicate validators participating on network
```

## When a doppelganger is detected

If any check finds a watched validator active on the network, Grandine stops. It does not restart
itself, unlike after most other runtime errors. The log shows the public keys involved:

```text
application runtime failed: Doppelganger validators detected on the network (public keys: [0x93...4a])
```

The process then exits with **exit code 1**. With the built-in validator client, this stops the
whole process, including the beacon node.

What to do:

1. Do not restart Grandine until you have found the other instance.
2. Find and stop the other instance that uses the listed keys: an old server, a container, a backup,
   a failover partner, or another client.
3. If you cannot find it, remove the listed keys from Grandine and keep them offline. A key that
   another machine is signing with must not be started here.
4. Once only one instance remains, start Grandine again. The check runs again from the start.

> **Warning:** Exit code 1 is also used for other startup failures, so a service manager cannot tell
> the difference. With systemd's `Restart=always` or Docker's `--restart always`, Grandine starts
> again, waits, detects the doppelganger again and exits again, in a loop. No messages are signed
> during this loop, but alert on the log line above so that you notice. See
> [Running as a service](./running_as_a_service.md).

## The cost

On every start with doppelganger protection, each validator misses its duties for about 2 to 3
epochs: the 2-epoch waiting period, plus the time until the next check after it ends. The missed
attestations cost roughly as much as being offline for the same time. A proposal or sync committee
duty that falls in that window is also missed.

For short restarts, such as an upgrade, you can disable doppelganger protection if you are sure no
other instance exists. Keep it on when keys have just moved.

## Command line options

- `--detect-doppelgangers` (default: disabled): enables doppelganger protection. With the built-in
  beacon node, it requires `--track-liveness`.
- `--track-liveness` (default: disabled): makes the beacon node record which validators attest and
  propose, and serve `POST /eth/v1/validator/liveness/{epoch}`. A beacon node option, not accepted
  by `grandine vc`.

See the [command line reference](./cli_options.md) for the full list.
