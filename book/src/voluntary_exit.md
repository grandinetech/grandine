# Voluntary exits, withdrawals and consolidations

This page covers how a validator's stake leaves the beacon chain or moves between validators:

- a **voluntary exit** stops a validator for good, and its full balance is then withdrawn;
- a **BLS-to-execution change** sets the withdrawal address of a validator that still has old BLS
  (`0x00`) withdrawal credentials;
- **withdrawals** pay balances to the withdrawal address automatically;
- **execution-layer requests** (EIP-7002 and EIP-7251) let the withdrawal address trigger exits,
  partial withdrawals and consolidations.

> **Warning:** An exit cannot be cancelled or undone. Once a validator has exited, its key can never
> validate again. Practice on the Hoodi testnet first.

## Withdrawals in brief

Withdrawals need execution-layer withdrawal credentials: `0x01` (classic) or `0x02` (compounding,
from the Electra fork on). Validators created with `0x00` credentials must first switch with a
[BLS-to-execution change](#bls-to-execution-change).

The beacon chain pays withdrawals automatically. No transaction and no fee is needed. Each block
processes the next validators in index order (the "sweep"), up to 16 withdrawals per block on
mainnet, and starts over from the first validator once it reaches the end. Depending on the size of
the validator set, it takes several days for the sweep to come around to the same validator.

- **Partial withdrawals (skimming).** For a `0x01` validator, any balance above 32 ETH is paid out
  on each pass of the sweep. For a `0x02` validator, only the balance above 2048 ETH is.
- **Full withdrawals.** After a validator has exited and become withdrawable, the sweep pays its
  whole balance.

Grandine needs no configuration for any of this. It follows the protocol rules like every other
consensus client.

## Voluntary exit

The protocol accepts an exit only from a validator that has spent 256 epochs or more in the active
set, which is about 27 hours on Mainnet. After the exit is included in a block, the validator joins the exit queue. It keeps performing
its duties until its exit epoch, so keep it running until then. After it exits, it becomes
withdrawable about 256 epochs (about 27 hours) later, and the next pass of the sweep pays the
balance.

Grandine has no exit subcommand. You create a signed exit through the Keymanager API and submit it
to a beacon node. This works with the integrated validator client and with `grandine vc`, for any
key Grandine signs with, including keys held by a [Web3Signer](./web3signer.md).

### Step 1: create the signed exit

Start Grandine with the validator API enabled (`--enable-validator-api`). It listens on
`127.0.0.1:5055` by default and requires the bearer token from `api-token.txt` in the validator
directory. See [Keymanager API](./keymanager_api.md).

```bash
TOKEN=$(cat ~/.grandine/mainnet/validator/api-token.txt)
PUBKEY=0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a

curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:5055/eth/v1/validator/$PUBKEY/voluntary_exit \
  > exit.json
```

The response holds the signed exit message:

```json
{
  "data": {
    "message": { "epoch": "123456", "validator_index": "4242" },
    "signature": "0x..."
  }
}
```

By default the exit is for the current epoch. Add `?epoch=EPOCH` to the URL to choose another epoch.
An exit with a future epoch only becomes valid when that epoch arrives.

This endpoint only signs. It does **not** publish the exit, so nothing happens until step 2. Keep the
file private: anyone who holds it can publish it.

The request fails with `404` if the key is not loaded in this Grandine instance, or if the beacon
chain does not know the validator yet.

### Step 2: submit it to a beacon node

Send the `data` part of the response to the beacon node's pool endpoint:

```bash
jq '.data' exit.json > signed_exit.json

curl -X POST -H "Content-Type: application/json" \
  -d @signed_exit.json \
  http://127.0.0.1:5052/eth/v1/beacon/pool/voluntary_exits
```

Any consensus client's beacon node accepts it. A Grandine beacon node validates the exit, adds it to
its pool and publishes it to the network. An invalid exit, for example one for a validator that has
not been active for 256 epochs, is rejected with an error message.

### Step 3: track the exit

Watch the validator's status with the [Beacon Node API](./beacon_node_api.md):

```bash
curl http://127.0.0.1:5052/eth/v1/beacon/states/head/validators/$PUBKEY
```

The status changes from `active_ongoing` to `active_exiting` once the exit is included, then to
`exited_unslashed`, `withdrawal_possible` and finally `withdrawal_done`. A block explorer such as
beaconcha.in shows the same.

Keep the validator running until its status is `exited_unslashed`. Until then it still has duties,
and missing them costs rewards.

### Other tools

Tools outside Grandine can also sign exits, for example offline from the mnemonic or a keystore.
The [ethstaker-deposit-cli](https://github.com/ethstaker/ethstaker-deposit-cli) does it with
[`exit-transaction-keystore`](https://deposit-cli.ethstaker.cc/exit_transaction_keystore.html) and
[`exit-transaction-mnemonic`](https://deposit-cli.ethstaker.cc/exit_transaction_mnemonic.html), and
[ethdo](https://github.com/wealdtech/ethdo) can do it too. Submit their output with step 2.

## BLS-to-execution change

Withdrawals need an execution address to go to, and `0x00` credentials do not contain one, so such a
validator is never paid out. A one-time BLS-to-execution change, signed with the withdrawal key derived from your mnemonic, sets a
`0x01` address. It can be done only once and cannot be changed later.

Grandine does not hold the withdrawal key, so it cannot sign this message. Generate it offline, for
example with the ethstaker-deposit-cli `generate-bls-to-execution-change` command, then submit the
resulting JSON array to the beacon node:

```bash
curl -X POST -H "Content-Type: application/json" \
  -d @bls_to_execution_change.json \
  http://127.0.0.1:5052/eth/v1/beacon/pool/bls_to_execution_changes
```

The endpoint takes a JSON array, so one file can carry changes for many validators. Each change is
validated, and if some fail, the response lists them by their index in the array.

> **Warning:** Double-check the execution address before you submit. A wrong address cannot be
> corrected, and everything the validator ever withdraws goes there.

## Execution-layer requests (EIP-7002 and EIP-7251)

Since the Electra fork, the owner of the withdrawal address can act from the execution layer. These
requests are transactions to system contracts on the execution chain, sent from the withdrawal
address and paying a small, dynamic fee. They do not go through Grandine's APIs at all. The
execution client puts them into the payload, and the beacon chain processes them in the block.

- **Exit (EIP-7002).** The withdrawal address can exit a validator without the validator's signing
  key. This helps when the signing key is lost or held by an operator you no longer trust.
- **Partial withdrawal (EIP-7002).** A `0x02` validator can withdraw part of its balance above
  32 ETH on request, instead of waiting for the sweep.
- **Consolidation (EIP-7251).** Moves the balance of one validator into another with the same
  withdrawal address, so fewer validators can hold more stake (up to 2048 ETH each). A request whose
  source and target are the same validator switches it from `0x01` to `0x02` credentials.

Use a tool or interface that supports these contracts, such as the staking launchpad or a wallet
with that feature, and check that it targets the right network. Grandine needs no option for them.
After the request is included, track the validator's status as in
[step 3](#step-3-track-the-exit).

## Related pages

- [Keymanager API](./keymanager_api.md) for the API token and other endpoints.
- [Managing validator keys](./key_management.md) for removing keys after an exit.
- [Becoming a validator](./validator_overview.md) for withdrawal credentials when you create keys.
- [Beacon Node API](./beacon_node_api.md) for the pool and validator status endpoints.

## Command line options

- `--enable-validator-api` (default: disabled): enables the validator (Keymanager) API, needed to
  sign exits.
- `--validator-api-address` (default: `127.0.0.1`): address of the validator API.
- `--validator-api-port` (default: `5055`): port of the validator API.
- `--validator-api-token-file` (default: `api-token.txt` in the validator directory): file with the
  bearer token.
- `--http-address` (default: `127.0.0.1`) and `--http-port` (default: `5052`): address of the beacon
  node API that accepts the signed exit.

See the [command line reference](./cli_options.md) for the full list.
