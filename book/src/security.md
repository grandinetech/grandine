# Security best practices

A validator holds keys that control real funds and can be slashed. A beacon node exposes APIs that
can leak information or be abused. This page collects the measures that matter most when you run
Grandine. None of them is exotic; most are about not exposing things you do not need to expose.

## APIs and ports

Grandine has three HTTP servers. All three listen on localhost by default.

| Server | Default | Enabled by | Authentication |
| --- | --- | --- | --- |
| Beacon Node API | `127.0.0.1:5052` | on by default (`--disable-http-api` turns it off) | none |
| Validator API (Keymanager API) | `127.0.0.1:5055` | `--enable-validator-api` | bearer token |
| Metrics | `127.0.0.1:5054` | `--metrics` | none |

### Beacon Node API

The Beacon Node API has no authentication. Besides the standard endpoints, it serves endpoints that
change the running node: `PATCH /features` toggles [runtime features](./runtime_features.md), and
`POST /eth/v2/debug/tracing/log_level` changes log levels. Anyone who can reach it can also submit
blocks and operations, read your validators' indices from duty requests, and put load on the node
with costly requests.

- Keep `--http-address 127.0.0.1` (the default) unless validator clients on other hosts need the
  API. In that case bind it to a private interface, such as a LAN, VPN or WireGuard address, never to
  a public one.
- If a browser-based tool needs the API, list only its origin in `--http-allowed-origins`. The
  default allows only the API's own URL.
- If you must reach the API over an untrusted network, put it behind a reverse proxy that adds TLS
  and authentication. Grandine itself serves plain HTTP.

```bash
# A beacon node that serves validator clients on a private network
grandine bn --network mainnet --http-address 10.0.0.5 --http-port 5052 ...
```

### Validator API and the API token

The validator API (`--enable-validator-api`) serves the [Keymanager API](./keymanager_api.md): it
can import and delete keys and change fee recipients. Every request needs the header
`Authorization: Bearer TOKEN`.

- By default the token is read from `api-token.txt` in the validator directory
  (`$HOME/.grandine/NETWORK/validator/api-token.txt`). If that file does not exist, Grandine
  generates a random 256-bit token and writes it there as hex. The startup log shows the path:
  `Validator API is listening on ..., authorization token file: ...`.
- With `--validator-api-token-file`, Grandine reads the token from your file and does not create
  one.
- The generated file is created with default permissions (subject to your umask). Restrict it:

```bash
chmod 600 ~/.grandine/mainnet/validator/api-token.txt
```

Treat the token like a password. Keep the validator API on localhost, and enable it only when you
use it.

### Metrics

The metrics endpoint has no authentication and allows any origin. It reveals the node's version,
resources, peers and validator activity. Bind it to localhost or a monitoring network only. See
[Metrics](./metrics.md).

### Firewall

Open only the peer-to-peer ports to the internet. A typical setup with `ufw`:

```bash
# Peer-to-peer: libp2p TCP, discovery UDP, QUIC UDP
sudo ufw allow 9000/tcp
sudo ufw allow 9000/udp
sudo ufw allow 9001/udp

# If you listen on IPv6 as well
sudo ufw allow 9050/tcp
sudo ufw allow 9050/udp
sudo ufw allow 9051/udp

sudo ufw default deny incoming
sudo ufw enable
```

| Port | Protocol | Purpose | Expose to the internet? |
| --- | --- | --- | --- |
| 9000 | TCP | libp2p (`--libp2p-port`) | Yes |
| 9000 | UDP | discovery (`--discovery-port`) | Yes |
| 9001 | UDP | QUIC (`--quic-port`) | Yes |
| 9050, 9051 | TCP/UDP, UDP | the same over IPv6 | Yes, if you use IPv6 |
| 5052 | TCP | Beacon Node API | No |
| 5054 | TCP | Metrics | No |
| 5055 | TCP | Validator API | No |
| 8551 | TCP | Execution client Engine API (on the EL) | No |

See [Default ports and paths](./default_ports.md) and [Networking and peers](./networking.md).

> **Note:** Docker publishes ports with its own iptables rules, which bypass `ufw`. Publish API
> ports on the loopback address only, for example `-p 127.0.0.1:5052:5052`, or do not publish them.

## The Engine API and the JWT secret

Grandine authenticates to the execution client's Engine API with a shared JWT secret. Grandine
does not create the secret; create it once and give the same file to both clients:

```bash
sudo mkdir -p /secrets
openssl rand -hex 32 | tr -d "\n" | sudo tee /secrets/jwt.hex > /dev/null
sudo chmod 600 /secrets/jwt.hex
```

```bash
grandine --network mainnet --eth1-rpc-urls http://127.0.0.1:8551 --jwt-secret /secrets/jwt.hex ...
```

Make the file readable only by the users that run the two clients. Keep the Engine API port (8551)
off the internet. See [Connecting an execution client](./execution_client.md).

## Validator keys

### Generate keys offline

Generate validator keys and mnemonics on a machine that is not connected to the network, ideally
one booted from a live USB system that you wipe afterwards, using the official
[ethstaker-deposit-cli](https://github.com/ethstaker/ethstaker-deposit-cli). Write the mnemonic
on paper and store it somewhere safe. Never type it on the validator machine. Copy only the
keystore files and the deposit data off the offline machine. See
[Becoming a validator](./validator_overview.md).

Set the withdrawal credentials to an execution address you control at deposit time, so that a
compromise of the validator machine cannot redirect withdrawals.

### File permissions

Run Grandine as a dedicated, unprivileged user that owns its data directory, and make sure no other
user can read keys or passwords:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin grandine
sudo chown -R grandine:grandine /var/lib/grandine
sudo chmod 700 /var/lib/grandine
sudo chmod 600 /path/to/password.txt
```

What Grandine does itself:

- Password files it writes for keystores imported through the Keymanager API are created with mode
  `0600`, in the `secrets` directory.
- `validators.yml` is created readable by its owner only; when Grandine rewrites an existing file it
  keeps that file's permissions.
- Keystore files are encrypted, so Grandine writes them with default permissions.

Keystores you give with `--keystore-dir`, the password file or directory
(`--keystore-password-file`, `--keystore-password-dir`) and the keystore storage password
(`--keystore-storage-password-file`) are your responsibility. Give them `0600` (files) and `0700`
(directories). See [Running as a service](./running_as_a_service.md) and
[Validator definitions](./validator_definitions.md).

> **Note:** The Docker images run Grandine as `root` inside the container, with data in
> `/root/.grandine`. Use the host's file permissions on the mounted directories to protect keys, and
> consider running the container with `--user` and a matching data directory.

### Remote signing

With a remote signer, the validator machine never holds the private keys. Grandine supports
[Web3Signer](./web3signer.md) through `--web3signer-urls`. Keys then live on a separate, locked-down
host, which can also enforce its own slashing protection. This is the recommended setup for large
or institutional operations.

### Slashing safety

The most common way to get slashed is to run the same keys in two places at once, often during a
migration or a failover. Never do that.

- Keep [slashing protection](./slashing_protection.md) data whenever keys move, and import it before
  the keys sign anything.
- Enable [doppelganger protection](./doppelganger_protection.md).
- Do not build automatic failover of validator clients. Use redundant beacon nodes instead. See
  [Redundancy and fallback beacon nodes](./redundancy.md).
- Follow the [migration](./migration.md) procedure when you move validators.

## Host hardening

- Keep the OS and Grandine up to date. Enable automatic security updates for the OS.
- Use SSH keys, disable password and root logins, and consider a non-standard SSH port and
  `fail2ban`.
- Run only what the node needs on the machine.
- Use full-disk encryption if the machine could be physically stolen. Plan how the node unlocks
  after a reboot.
- Keep the system clock accurate with NTP (for example `chrony` or `systemd-timesyncd`). Validators
  with a wrong clock miss duties.
- Back up your mnemonic offline, and the slashing protection database (or an interchange export)
  regularly.

## Verifying downloads

Download Grandine only from the
[GitHub releases page](https://github.com/grandinetech/grandine/releases) or the
`sifrai/grandine` Docker Hub repository. To get the strongest assurance, build from source at a
release tag. See [Pre-built binaries and Docker](./downloads.md) and
[Building from source](./build_from_source.md). Releases do not publish checksum or signature
files, so you cannot verify a binary cryptographically.

When you deploy with Docker, use the `stable` tag, which only ever receives stable releases. For full
control over when the image changes, pin it by version tag or by digest
(`sifrai/grandine@sha256:...`).

## Security audits

Grandine has been reviewed by external security firms. The reports are in the
[`audit/`](https://github.com/grandinetech/grandine/tree/develop/audit) directory of the
repository:

- Matter Labs, Security Review Report, 2024-11-21
  (`Matter-Labs-Security-Review-Report-2024-11-21.pdf`).
- X41 D-Sec, Code Review of Grandine, Final Report, 2024-11-29
  (`X41-Code-Review-Grandine-Final-Report-2024-11-29.pdf`).

An audit covers the code at a point in time. Later changes are not covered.

## Reporting a vulnerability

Do not report security vulnerabilities in public GitHub issues or public channels. Contact the
Grandine team privately, by email at [info@grandine.io](mailto:info@grandine.io) or by a direct
message to the team on the [Grandine Discord](https://discord.gg/H9XCdUSyZd). Include the affected
version, the steps to reproduce the issue and its impact. See [Support](./support.md).

<!-- TODO(verify): the repository has no SECURITY.md and GitHub private vulnerability reporting is disabled; confirm with the team that info@grandine.io (the address in the crate metadata) is the right address for vulnerability reports. -->

## Command line options

See [Command line reference](./cli_options.md) for the full list.

- `--http-address`: default `127.0.0.1`. Address of the Beacon Node API.
- `--http-port`: default `5052`. Port of the Beacon Node API.
- `--http-allowed-origins`: default the API's own URL. Allowed CORS origins for the Beacon Node API.
- `--disable-http-api`: default disabled. Run without the Beacon Node API.
- `--enable-validator-api`: default disabled. Serve the validator API (Keymanager API).
- `--validator-api-address`: default `127.0.0.1`. Address of the validator API.
- `--validator-api-port`: default `5055`. Port of the validator API.
- `--validator-api-allowed-origins`: default the API's own URL. Allowed CORS origins for the validator API.
- `--validator-api-token-file`: default `{validator-dir}/api-token.txt`, generated if missing. File with the validator API token. A file you pass must already exist.
- `--metrics-address`: default `127.0.0.1`. Address of the metrics endpoint.
- `--jwt-secret`: default none. File with the hex-encoded JWT secret shared with the execution client.
- `--web3signer-urls`: default none. Web3Signer URLs for remote signing.
