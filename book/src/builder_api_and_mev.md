# Builder API and MEV

Specialized block builders assemble execution payloads that pay more than a payload your own
execution client builds. They compete for the right to fill your block and pay the proposer for
it. This value is called MEV (maximal extractable value). The [Builder
API](https://github.com/ethereum/builder-specs) is the standard interface between a consensus
client and these builders.

Grandine supports the Builder API and connects to exactly one builder URL. To reach several relays,
run a relay multiplexer such as [mev-boost](https://github.com/flashbots/mev-boost) or
[mev-rs](https://github.com/ralexstokes/mev-rs) and point Grandine at it.

Using a builder is optional. Without one, Grandine always builds blocks with your own execution
client, and you still receive the priority fees through your
[fee recipient](./fee_recipient.md).

## How it works (before Gloas)

1. **Registration.** Once per epoch, Grandine signs a validator registration for each validator: the
   fee recipient, the gas limit and a timestamp. It sends the registrations to the builder, so
   relays know where to pay you.
2. **Bidding.** When one of your validators proposes, Grandine asks the builder for a payload header
   (`/eth/v1/builder/header/...`), with a 1 second timeout (`--builder-header-timeout`). At the same time, it asks your
   execution client for a local payload.
3. **Selection.** Grandine compares the builder's bid with the value of the local payload, adjusted
   by the [builder boost factor](#builder-boost-factor). The more profitable one wins.
4. **Reveal.** If the builder wins, Grandine signs a blinded block and sends it to the builder,
   which returns the full payload and publishes the block.

If the builder has no bid, the request times out, or the circuit breaker is tripped, Grandine uses
the local payload. You do not lose the slot because a relay is down. A builder can still fail after
you sign a blinded block, by not revealing the payload in time, and then the block is missed.

## Setting up mev-boost

1. Install and start mev-boost on the same machine or network, with the relays you choose. For
   example:

   ```bash
   mev-boost -mainnet -relay-check \
     -relays https://0xRELAY_PUBKEY@RELAY-HOST,https://0xRELAY_PUBKEY_2@RELAY-HOST-2
   ```

   By default mev-boost listens on `localhost:18550`; `-addr` changes it. See the
   [mev-boost documentation](https://github.com/flashbots/mev-boost#readme) for current flags and
   relay lists.

2. Start Grandine with `--builder-url` pointing at mev-boost, and a fee recipient you control:

   ```bash
   grandine                                   \
     --network mainnet                        \
     --jwt-secret /path/to/jwt.hex            \
     --eth1-rpc-urls http://EL-HOST:8551      \
     --keystore-dir /path/to/validator_keys   \
     --keystore-password-file /path/to/password.txt \
     --suggested-fee-recipient 0xYOUR_EXECUTION_ADDRESS \
     --builder-url http://127.0.0.1:18550
   ```

   With Docker, make sure the container can reach mev-boost, for example by putting both on the
   same Docker network and using `--builder-url http://mev-boost:18550`.

3. Check the logs. When a validator proposes, Grandine logs whether the builder delivered:

   ```text
   received execution payload header from builder for slot 123456
   validator 4242 proposing beacon block with root 0x... in slot 123456 using the builder API
   ```

   or why it built locally:

   ```text
   builder has no execution payload header available for slot 123456
   using more profitable local payload: local MEV: ..., builder MEV: ..., boosted builder MEV: ..., builder_boost_factor: 100
   cannot use Builder API for execution payload header: 4 consecutive missing blocks since head
   ```

`--builder-api-url` is the deprecated name of `--builder-url`. It still works, with a warning. If
both are given, `--builder-url` wins.

## Data format

`--builder-format` sets the encoding Grandine uses with the builder: `ssz` (the default) or `json`.
With `ssz`, Grandine asks for SSZ but also accepts JSON responses. If the builder rejects SSZ
registrations, Grandine retries them in JSON and keeps using JSON for registrations from then on.
Set `--builder-format json` only if your builder or relay multiplexer has trouble with SSZ.

## Circuit breaker

When the chain is unhealthy, for example after several missed slots, builders are more likely to
fail. Grandine then stops asking the builder and builds locally. The checks run before every
proposal:

- If more than `--builder-max-skipped-slots` (default `3`) slots since the head block are empty,
  Grandine builds locally.
- If more than `--builder-max-skipped-slots-per-epoch` (default `8`) slots in the last 32 slots (one
  rolling epoch) are empty, Grandine builds locally.

Both thresholds are exclusive: with the default of 3, the fourth consecutive missing block trips the
breaker. When it trips, Grandine logs:

```text
cannot use Builder API for execution payload header: 4 consecutive missing blocks since head
cannot use Builder API for execution payload header: 9 missing blocks in the last rolling epoch
```

`--builder-disable-checks` turns the circuit breaker off, so the builder is always asked. This is not
recommended on mainnet.

## Builder boost factor

When Grandine has both a builder's bid and a locally built payload, it scales the bid's value by the
builder boost factor, a percentage, and then takes the payload that is worth more:

- `100` (the default): pick whichever pays more;
- `0`: always build locally;
- `90`: use the builder only if its bid, reduced by 10%, still beats the local payload. This favors
  local blocks a little, which helps censorship resistance;
- a very large value: always prefer the builder whenever it delivers a bid.

Set the default for all validators with `--default-builder-boost-factor`. Override it per validator
in [`validators.yml`](./validator_definitions.md):

```yaml
- enabled: true
  pubkey: "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a"
  type: local_keystore
  keystore_path: /path/to/validator_keys/keystore-0.json
  keystore_password_path: /path/to/secrets/keystore-0.txt
  builder_boost_factor: 90
```

Three per-validator fields exist. The first that applies wins:

1. `prefer_builder_proposals: true`: always prefer the builder (the factor becomes the maximum);
2. `builder_boost_factor: N`: use `N`;
3. `builder_proposals: false`: never use the builder (the factor becomes `0`);
4. otherwise, `--default-builder-boost-factor`.

## Validator registration

Registrations are sent once per epoch, in batches of up to 500, for every validator that has a fee
recipient. They use the fee recipient and gas limit that apply to each validator (see
[Fee recipient, graffiti and gas limit](./fee_recipient.md)). With the integrated validator client,
a validator without its own fee recipient is registered with `--suggested-fee-recipient`, or else
with the Grandine donation address, so always set your own.

A Grandine beacon node also accepts registrations from remote validator clients through
`POST /eth/v1/validator/register_validator`, and forwards them to its builder together with its own.

Registration failures are logged as warnings:

```text
failed to register validator batch: ...
```

## Separate validator client

The builder options above are beacon node options. `grandine vc` refuses them: the builder is
configured on the beacon nodes it connects to. The validator client opts in with `--use-builder`:

```bash
grandine vc                                      \
  --network mainnet                              \
  --beacon-node-urls http://BN-HOST:5052         \
  --keystore-dir /path/to/validator_keys         \
  --keystore-password-file /path/to/password.txt \
  --suggested-fee-recipient 0xYOUR_EXECUTION_ADDRESS \
  --use-builder
```

With `--use-builder`, the validator client signs registrations and sends them to its beacon nodes
through `POST /eth/v1/validator/register_validator`. It also passes each validator's builder boost
factor with its block requests. Without `--use-builder`, it asks only for local payloads (a boost
factor of `0`) and sends no registrations, because a beacon node without a builder rejects them.

With `grandine vc`, a validator without a fee recipient is not registered at all. See
[Validator client](./validator_client.md).

## At the Gloas fork (ePBS)

The Gloas fork brings enshrined proposer-builder separation (ePBS, EIP-7732). Builders become part
of the protocol: they bid for blocks over the peer-to-peer network, and the execution payload is
published separately from the beacon block. At the time of writing, this Grandine version schedules
Gloas on Sepolia and Hoodi, but not on mainnet. What changes in Grandine:

- **Bids come from gossip.** The beacon node picks the highest bid it has seen for the slot.
  `--builder-url` and validator registrations are no longer used for this. Grandine stops sending
  registrations once Gloas is active.
- **Proposer preferences.** Instead of registrations, the validator client publishes signed proposer
  preferences (fee recipient and gas limit) for its upcoming proposals, starting one epoch before
  the fork. Validators without a fee recipient get none.
- **Boost factor.** The builder boost factor still applies. Grandine compares the bid with the value
  of a local payload in the same way. With a factor of `0`, it always builds the payload itself.
- **Circuit breaker.** Missing blocks are no longer the signal. Grandine instead counts canonical
  blocks whose builder did not reveal the payload in time, judged only for blocks that at least 60%
  of the committee attested. The same options set the thresholds:
  `--builder-max-skipped-slots` for consecutive withheld payloads and
  `--builder-max-skipped-slots-per-epoch` for the last rolling epoch. When it trips, Grandine builds
  payloads locally for one epoch, or less if builders recover first:

  ```text
  builders withheld 4 payloads in a row, building payloads locally
  ```

  `--builder-disable-checks` disables this check too.
- **`--use-builder` on `vc`** matters only until Gloas. From Gloas on, a separate validator client
  always lets its beacon nodes consider builder bids, with the validator's boost factor.

## Command line options

Beacon node options (not accepted by `grandine vc`):

- `--builder-url` (default: none): URL of the external block builder or relay multiplexer.
- `--builder-api-url` (deprecated): old name of `--builder-url`.
- `--builder-format` (default: `ssz`): data format for the Builder API, `ssz` or `json`.
- `--builder-header-timeout` (default: `1000`): timeout in milliseconds for fetching a payload
  header from the builder. Must be greater than `0`. Relevant only until Gloas.
- `--builder-disable-checks` (default: disabled): always use the builder, without circuit breaker
  checks.
- `--builder-max-skipped-slots` (default: `3`): consecutive missing blocks (withheld payloads from
  Gloas on) tolerated before building locally.
- `--builder-max-skipped-slots-per-epoch` (default: `8`): missing blocks (withheld payloads from
  Gloas on) in the last rolling epoch tolerated before building locally.

Options for both the beacon node and the validator client:

- `--default-builder-boost-factor` (default: `100`): the percentage by which a builder's bid is
  scaled before Grandine weighs it against the local payload.
- `--suggested-fee-recipient` (default: none; plain `grandine` and `grandine bn` fall back to the
  Grandine donation address, `grandine vc` has no fallback): fee recipient used in registrations
  and payloads. Set your own, or priority fees and MEV payments can go to the donation address.
- `--default-gas-limit` (default: the scheduled gas limit, or `60000000`): gas limit used in
  registrations.

Validator client option (`grandine vc` only):

- `--use-builder` (default: disabled): register validators with the builder behind the beacon nodes
  and accept its payloads. Relevant only until Gloas.

See the [command line reference](./cli_options.md) for the full list.
