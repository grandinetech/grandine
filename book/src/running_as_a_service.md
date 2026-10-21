# Running as a service

A node should start on boot, restart after a crash and run without a terminal. This page shows two
ways to do that: a systemd service for the binary, and Docker Compose for containers.

Both examples run on Mainnet. For Hoodi, replace `mainnet` with `hoodi` and use a Hoodi checkpoint
sync endpoint.

## systemd

### 1. Create a dedicated user

Run Grandine as its own unprivileged user, not as `root` and not as your login user. If the node is
ever compromised, the damage stays inside that user's files.

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin grandine
sudo mkdir -p /var/lib/grandine
sudo chown grandine:grandine /var/lib/grandine
sudo chmod 700 /var/lib/grandine
```

Grandine appends the network name to `--data-dir`, so with `--data-dir /var/lib/grandine` the Mainnet
data lives in `/var/lib/grandine/mainnet`.

### 2. Share the JWT secret

The execution client and Grandine must both read the JWT secret. If they run as different users, put
the secret in a group that both belong to. This example assumes the execution client runs as the user
`geth`:

```bash
sudo groupadd --system ethereum
sudo usermod -aG ethereum grandine
sudo usermod -aG ethereum geth

sudo mkdir -p /var/lib/ethereum
openssl rand -hex 32 | tr -d "\n" | sudo tee /var/lib/ethereum/jwt.hex > /dev/null
sudo chown root:ethereum /var/lib/ethereum/jwt.hex
sudo chmod 640 /var/lib/ethereum/jwt.hex
```

### 3. Write the unit file

Create `/etc/systemd/system/grandine.service`:

```ini
[Unit]
Description=Grandine Ethereum consensus client
Documentation=https://docs.grandine.io/
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=grandine
Group=grandine
ExecStart=/usr/local/bin/grandine \
  --network mainnet \
  --data-dir /var/lib/grandine \
  --eth1-rpc-urls http://127.0.0.1:8551 \
  --jwt-secret /var/lib/ethereum/jwt.hex \
  --checkpoint-sync-url CHECKPOINT-URL

# Restart after a crash, but not in a tight loop.
Restart=on-failure
RestartSec=10

# Grandine saves its chain on SIGTERM. Give it time before systemd kills it.
TimeoutStopSec=300

LimitNOFILE=65536

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/var/lib/grandine

[Install]
WantedBy=multi-user.target
```

The `ProtectHome` and `ReadWritePaths` settings stop Grandine from writing outside its data
directory. If you keep keystores or other files elsewhere, make sure the `grandine` user can read them.

> **Note:** `--checkpoint-sync-url` is only used when the database is empty, so it is safe to keep it in
> the unit. On later starts Grandine logs `skipping checkpoint sync: existing database found` and
> continues from its own data.

### 4. Start and enable the service

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now grandine
```

Check that it runs:

```bash
sudo systemctl status grandine
```

Follow the logs:

```bash
sudo journalctl -fu grandine
```

Show the logs since the last boot, or for a time range:

```bash
sudo journalctl -u grandine -b
sudo journalctl -u grandine --since "1 hour ago"
```

journald rotates the logs for you. To limit how much disk they use, set `SystemMaxUse=` in
`/etc/systemd/journald.conf`. See [Logging](./logging.md) for log levels.

### Keep the options in a file

Long command lines are hard to maintain. `--args-file` loads options from a YAML file, with long option
names as keys. Options given on the command line win over the file.

Create `/etc/grandine/mainnet.yaml`:

```yaml
network: mainnet
data-dir: /var/lib/grandine
eth1-rpc-urls:
  - http://127.0.0.1:8551
jwt-secret: /var/lib/ethereum/jwt.hex
checkpoint-sync-url: CHECKPOINT-URL
metrics: true
```

A `true` value turns on a flag, `false` leaves it off, and a list repeats the option once per value.
Then use:

```ini
ExecStart=/usr/local/bin/grandine --args-file /etc/grandine/mainnet.yaml
```

### Adding validators

To run the integrated validator client, add your keystore options to `ExecStart` or to the args file,
for example:

```yaml
keystore-dir: /var/lib/grandine/keys
keystore-password-file: /var/lib/grandine/secrets/password.txt
suggested-fee-recipient: "FEE-RECIPIENT-ADDRESS"
```

Quote execution addresses in YAML so they stay strings. Make the keystores and password files
readable only by the `grandine` user:

```bash
sudo chown -R grandine:grandine /var/lib/grandine/keys /var/lib/grandine/secrets
sudo chmod 700 /var/lib/grandine/keys /var/lib/grandine/secrets
sudo chmod 600 /var/lib/grandine/keys/* /var/lib/grandine/secrets/*
```

See [Validator client](./validator_client.md) and [Managing validator keys](./key_management.md).

### A separate validator client

To run the validator client as its own service, for example against a beacon node on another
machine, create a second unit with its own user and data directory:

```ini
[Unit]
Description=Grandine validator client
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=grandine-vc
Group=grandine-vc
ExecStart=/usr/local/bin/grandine vc \
  --network mainnet \
  --data-dir /var/lib/grandine-vc \
  --beacon-node-urls http://BEACON-NODE-HOST:5052 \
  --keystore-dir /var/lib/grandine-vc/keys \
  --keystore-password-file /var/lib/grandine-vc/secrets/password.txt \
  --suggested-fee-recipient FEE-RECIPIENT-ADDRESS
Restart=on-failure
RestartSec=10
TimeoutStopSec=120
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/var/lib/grandine-vc

[Install]
WantedBy=multi-user.target
```

The options come after `vc`. The beacon node behind `--beacon-node-urls` can be `grandine bn` or any
other consensus client.

> **Warning:** Never run the same keys in the beacon node's integrated validator client and in a
> separate `grandine vc`, and never give two validator clients the same data directory. Either can get
> your validators slashed. If you move keys from the beacon node to a separate validator client, stop
> the beacon node, remove the keys from it, export the slashing protection data, import it into the
> new validator client and only then start it. See [Slashing protection](./slashing_protection.md).

### Exit codes and restarts

Grandine exits with status 1 when it fails and 2 when the command line is invalid. Many run-time
errors do not reach systemd at all: Grandine restarts its runtime inside the process and logs
`application runtime failed`. Errors that stop the process include a detected doppelganger. With
`Restart=on-failure`, systemd starts Grandine again after `RestartSec`, and doppelganger protection
runs again on the next start.

## Docker Compose

The Compose file below runs Geth and Grandine on Mainnet. The same pattern works for other execution
clients.

### 1. Prepare the directory

```bash
mkdir -p ~/eth-node/jwt
cd ~/eth-node
openssl rand -hex 32 | tr -d "\n" > jwt/jwt.hex
```

### 2. Write `docker-compose.yml`

```yaml
services:
  geth:
    image: ethereum/client-go:stable
    restart: unless-stopped
    stop_grace_period: 3m
    command:
      - --mainnet
      - --datadir=/data
      - --authrpc.addr=0.0.0.0
      - --authrpc.port=8551
      - --authrpc.vhosts=*
      - --authrpc.jwtsecret=/jwt/jwt.hex
    ports:
      - "30303:30303/tcp"
      - "30303:30303/udp"
    volumes:
      - ./geth-data:/data
      - ./jwt:/jwt:ro

  grandine:
    image: sifrai/grandine:stable
    restart: unless-stopped
    stop_grace_period: 2m
    depends_on:
      - geth
    command:
      - --network=mainnet
      - --eth1-rpc-urls=http://geth:8551
      - --jwt-secret=/jwt/jwt.hex
      - --checkpoint-sync-url=CHECKPOINT-URL
      - --http-address=0.0.0.0
      - --metrics
      - --metrics-address=0.0.0.0
    ports:
      - "9000:9000/tcp"
      - "9000:9000/udp"
      - "9001:9001/udp"
      - "127.0.0.1:5052:5052"
      - "127.0.0.1:5054:5054"
    volumes:
      - ./grandine-data:/root/.grandine
      - ./jwt:/jwt:ro
```

Replace `CHECKPOINT-URL` with a Mainnet checkpoint sync endpoint.

About this file:

- `restart: unless-stopped` restarts a container after a crash or a reboot, unless you stopped it.
- `stop_grace_period` gives each client time to shut down cleanly. Docker's default is 10 seconds,
  which is too short.
- The Engine API (8551) is reachable only inside the Compose network, not from the host.
- `--http-address=0.0.0.0` makes the Beacon Node API listen inside the container. The port mapping
  `127.0.0.1:5052:5052` publishes it on the host's loopback interface only. Do the same for the
  metrics port 5054.
- The peer-to-peer ports 9000 (TCP and UDP) and 9001 (UDP) are published on all interfaces so that
  peers can reach the node.
- `./grandine-data` holds Grandine's data in `./grandine-data/mainnet`.

### 3. Start the stack

```bash
docker compose up -d
docker compose logs -f grandine
```

Check the sync status from the host:

```bash
curl -s http://127.0.0.1:5052/eth/v1/node/syncing
```

### Adding validators in Compose

Mount the keystores and the password file read-only and add the options:

```yaml
    command:
      # ... the options above, plus:
      - --keystore-dir=/keys
      - --keystore-password-file=/secrets/password.txt
      - --suggested-fee-recipient=FEE-RECIPIENT-ADDRESS
    volumes:
      - ./grandine-data:/root/.grandine
      - ./jwt:/jwt:ro
      - ./validator_keys:/keys:ro
      - ./secrets:/secrets:ro
```

The slashing protection database lives in `./grandine-data/mainnet/validator`. Back it up along with
the rest of the data directory; see [Slashing protection](./slashing_protection.md).

To update the images, see [Updating Grandine](./updating.md).

## Command line options

- `--args-file`: no default. YAML file with options, keyed by long option name.
- `--data-dir`: default `$HOME/.grandine`. Parent directory for data; the network name is appended.
- `--http-address`: default `127.0.0.1`. Address the Beacon Node API listens on.
- `--http-port`: default `5052`. Port of the Beacon Node API.
- `--metrics`: default disabled. Serve Prometheus metrics.
- `--metrics-address`: default `127.0.0.1`. Address of the metrics endpoint.
- `--metrics-port`: default `5054`. Port of the metrics endpoint.
- `--beacon-node-urls` (`vc` only): required. Beacon Node API URLs for the separate validator client.

See the [Command line reference](./cli_options.md) for the full list.
