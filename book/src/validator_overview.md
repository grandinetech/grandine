# Becoming a validator

This page walks through the whole path from no keys to an active validator run by Grandine. The steps are the same on every network. Do them on the Hoodi testnet first. Testnet ETH is free, mistakes cost nothing, and you learn how your setup behaves before real funds are at stake.

The simplest setup runs everything in one process: plain `grandine` with validator keys is a beacon node with the validator client built in. That is what this page uses. Grandine can also run the validator client as a separate process (`grandine vc`). See [Validator client](./validator_client.md) for when that makes sense.

You need:

- a synced execution client connected to Grandine through the Engine API and a JWT secret (see [Connecting an execution client](./execution_client.md));
- Grandine installed (see [Installation overview](./installation.md));
- 32 ETH per validator on mainnet, or Hoodi test ETH from a faucet (see [Supported networks](./networks.md));
- an execution-layer address you control for withdrawals and block rewards.

> **Warning:** A validator key must only ever be active in one place. Running the same key in two validator clients at the same time gets the validator slashed: it loses part of its stake and is forcibly exited. Read [Slashing protection](./slashing_protection.md) before you move keys between machines or clients.

## 1. Generate validator keys

Generate keys with [ethstaker-deposit-cli](https://github.com/ethstaker/ethstaker-deposit-cli). Do it on an offline machine if you can, and write the mnemonic down on paper. The mnemonic can regenerate every key and the withdrawal credentials, so anyone who has it controls the funds.

Download a release for your platform from the project's GitHub releases page, verify its checksum, and run:

```bash
./deposit new-mnemonic --chain hoodi
```

For mainnet use `--chain mainnet`. The tool asks for the number of validators, a keystore password and a withdrawal address; `--num_validators`, `--keystore_password` and `--withdrawal_address` set them without prompts. It creates compounding (`0x02`) validators by default and asks for the deposit amount per validator; `--regular_withdrawal` creates `0x01` validators with 32 ETH each. See the [ethstaker-deposit-cli documentation](https://deposit-cli.ethstaker.cc/new_mnemonic.html) for all options.

The tool writes a `validator_keys` directory that contains:

- one EIP-2335 keystore per validator, named like `keystore-m_12381_3600_0_0_0-1700000000.json`;
- a `deposit_data-<timestamp>.json` file for the launchpad.

Every keystore created in one run shares the password you entered. Store that password in a file that only the Grandine user can read:

```bash
printf '%s' 'YOUR-KEYSTORE-PASSWORD' > /path/to/password.txt
chmod 600 /path/to/password.txt
```

Grandine strips control characters from keystore passwords, as EIP-2335 requires, so a trailing newline in the file does no harm.

## 2. Make the deposit with the launchpad

Open the Staking Launchpad for your network:

- Mainnet: <https://launchpad.ethereum.org>
- Hoodi: <https://hoodi.launchpad.ethereum.org>

Follow its steps, upload `deposit_data-<timestamp>.json`, and send the deposit transaction from your wallet. Check that the launchpad URL is right before you connect a wallet. Phishing copies of the launchpad exist.

You can leave `deposit_data-<timestamp>.json` in `validator_keys`. Grandine skips files whose names start with `deposit_data` when it scans the keystore directory, and logs a warning about them.

## 3. Start Grandine with your keys

Start Grandine once the beacon node is set up as in the [Quick start](./quick_start.md), and add the keystore directory and password file. Set a fee recipient too, so that rewards from proposed blocks go to an address you control.

```bash
grandine \
  --network hoodi \
  --eth1-rpc-urls http://EL-HOST:8551 \
  --jwt-secret /path/to/jwt.hex \
  --checkpoint-sync-url CHECKPOINT-SYNC-URL \
  --keystore-dir /path/to/validator_keys \
  --keystore-password-file /path/to/password.txt \
  --suggested-fee-recipient 0xYOUR-EXECUTION-ADDRESS
```

With Docker, mount the keys and the password file and pass the same options. The image's entrypoint is `grandine`, so the options follow the image name directly:

```bash
docker run -d --name grandine \
  --network host \
  -v $HOME/.grandine:/root/.grandine \
  -v /path/to/jwt.hex:/jwt.hex:ro \
  -v /path/to/validator_keys:/validator_keys:ro \
  -v /path/to/password.txt:/password.txt:ro \
  sifrai/grandine:stable \
  --network hoodi \
  --eth1-rpc-urls http://127.0.0.1:8551 \
  --jwt-secret /jwt.hex \
  --checkpoint-sync-url CHECKPOINT-SYNC-URL \
  --keystore-dir /validator_keys \
  --keystore-password-file /password.txt \
  --suggested-fee-recipient 0xYOUR-EXECUTION-ADDRESS
```

Grandine refuses to run validators without `--eth1-rpc-urls`, because it cannot produce blocks without an execution client.

> **Warning:** Without a fee recipient, from `--suggested-fee-recipient` or set per validator, the integrated validator client pays the execution rewards of proposed blocks to the Grandine donation address `0xe7cf7C3BA875Dd3884Ed6a9082d342cb4FBb1f1b`. Always set your own. See [Fee recipient, graffiti and gas limit](./fee_recipient.md).

On startup, look for these log lines:

```text
started loading validator keys
decrypted validator key 0x...
loaded 1 validator key(s)
```

If these lines are missing, or Grandine logs `failed to load validator keys`, it found no keys: check the paths and that the keystore directory contains the keystores.

Grandine records every validator it loads in `validators.yml` in its validator directory (`~/.grandine/hoodi/validator` here). See [Validator definitions](./validator_definitions.md). Other ways to load keys, such as a password directory, the Keymanager API and Web3Signer, are covered in [Managing validator keys](./key_management.md).

> **Tip:** Decrypting many keystores takes a while because the key derivation is slow on purpose. Add `--use-validator-key-cache` to restart faster. See [Managing validator keys](./key_management.md#validator-key-cache).

## 4. Wait for activation

The deposit has to be seen by the beacon chain, and then the validator waits in the activation queue. Depending on the queue, this takes from hours to weeks. Keep Grandine running in the meantime. A validator that is not active yet has no duties, so nothing is lost.

Run Grandine as a service so that it survives reboots: see [Running as a service](./running_as_a_service.md).

## 5. Check the validator's status

Ask the beacon node through the [Beacon Node API](./beacon_node_api.md), which listens on `127.0.0.1:5052` by default:

```bash
curl -s http://127.0.0.1:5052/eth/v1/beacon/states/head/validators/0xYOUR-VALIDATOR-PUBKEY | jq .data.status
```

The status moves through `pending_initialized` (deposit seen), `pending_queued` (in the activation queue) and `active_ongoing` (attesting). If the request answers with a "not found" error, the deposit has not been processed yet.

You can also look the validator up on a block explorer such as beaconcha.in, which shows the queue position and an estimated activation time.

Once the validator is active, check that it attests: see [Monitoring validator performance](./validator_monitoring.md).

## Mainnet readiness checklist

Go through this list before you deposit on mainnet:

- [ ] You ran the same setup on Hoodi and saw validators attest for several days.
- [ ] Grandine is on the latest release. See [Updating Grandine](./updating.md).
- [ ] The execution client is fully synced and Grandine connects to it with the JWT secret.
- [ ] The beacon node is synced and has a healthy number of peers, with its P2P ports reachable. See [Networking and peers](./networking.md).
- [ ] The validator keys load at startup and the fee recipient is an address you control.
- [ ] Grandine runs as a service under a dedicated user and restarts on failure. See [Running as a service](./running_as_a_service.md).
- [ ] Metrics and alerts are set up, so you notice missed duties. See [Metrics](./metrics.md) and [Monitoring validator performance](./validator_monitoring.md).
- [ ] The mnemonic is stored offline, and the keystore password file is readable only by the Grandine user.
- [ ] You know how to export slashing protection data and you back it up before any migration. See [Slashing protection](./slashing_protection.md).
- [ ] The keys run in exactly one place. No old client, backup machine or second Grandine has them loaded.
- [ ] Optional: [Doppelganger protection](./doppelganger_protection.md) is enabled, so a restart never signs while the same key is live elsewhere.

## What next?

- [Running as a service](./running_as_a_service.md)
- [Managing validator keys](./key_management.md)
- [Fee recipient, graffiti and gas limit](./fee_recipient.md)
- [Builder API and MEV](./builder_api_and_mev.md)
- [Monitoring validator performance](./validator_monitoring.md)
- [Updating Grandine](./updating.md)
- [Voluntary exits, withdrawals and consolidations](./voluntary_exit.md)

## Command line options

- `--keystore-dir` (no default): directory with EIP-2335 keystore files to load.
- `--keystore-password-file` (no default): file with the password for all keystores.
- `--suggested-fee-recipient` (no default): default fee recipient for all validators.
- `--use-validator-key-cache` (disabled): cache decrypted keys for faster restarts.
- `--eth1-rpc-urls` (no default): execution client Engine API URLs; required when validators are loaded.

See [Command line reference](./cli_options.md) for the full list.
