# Networking and peers

Grandine talks to other consensus clients over libp2p. It finds peers with the discv5 discovery
protocol, exchanges blocks, attestations and other messages over gossipsub, and requests missing
data with request-response protocols. A beacon node needs a healthy number of peers to sync, to
follow the head, and to publish its validators' messages in time.

## Ports

| Port | Protocol | Purpose | Option |
|---|---|---|---|
| 9000 | TCP | libp2p (IPv4) | `--libp2p-port` |
| 9000 | UDP | discv5 discovery (IPv4) | `--discovery-port` |
| 9001 | UDP | libp2p over QUIC (IPv4) | `--quic-port` |
| 9050 | TCP | libp2p (IPv6) | `--libp2p-port-ipv6` |
| 9050 | UDP | discv5 discovery (IPv6) | `--discovery-port-ipv6` |
| 9051 | UDP | libp2p over QUIC (IPv6) | `--quic-port-ipv6` |
| 5052 | TCP | Beacon Node API, local only by default | `--http-port` |
| 5054 | TCP | Prometheus metrics, local only, when `--metrics` is set | `--metrics-port` |

The IPv6 ports are used only when you enable IPv6 (see below). For all ports and paths, see
[Default ports and paths](./default_ports.md).

Grandine checks at startup that its ports are free. If one is taken, it exits with a message such as
`libp2p port (9000) is unavailable; make sure no other instance of the application is running or
specify a different port with --libp2p-port`.

QUIC is enabled by default and is used alongside TCP. When Grandine dials a boot node that
advertises a QUIC address, it tries QUIC first. `--disable-quic` turns QUIC off.

## Port forwarding and firewalls

For a node to receive incoming connections, the peer-to-peer ports must be reachable from the
internet. Nodes that only make outgoing connections still work, but they find good peers more
slowly and depend more on others.

1. Allow the ports in the host firewall. With `ufw`:

   ```bash
   sudo ufw allow 9000/tcp
   sudo ufw allow 9000/udp
   sudo ufw allow 9001/udp
   ```

2. If the machine is behind a home router, forward the same ports to the machine's LAN address.
   Grandine tries UPnP first (see below), but a manual port forward is more reliable.
3. With Docker, publish the ports:

   ```bash
   docker run ... -p 9000:9000/tcp -p 9000:9000/udp -p 9001:9001/udp sifrai/grandine:stable ...
   ```

Do not expose the Beacon Node API (5052) or the metrics port (5054) to the internet. See
[Security best practices](./security.md).

### UPnP

UPnP is enabled by default. Grandine asks the router to forward its ports and logs one of:

```text
UPnP route established
UPnP not available
UPnP is available but gateway is not exposed to public network
```

`--disable-upnp` turns it off. If you set ENR options manually while UPnP is on, Grandine warns
`UPnP enabled with manual ENR settings: ...; manual ENR settings might be overridden by UPnP`. Turn
UPnP off when you forward ports by hand and set the ENR yourself.

## ENR and node identity

Other nodes find yours through its Ethereum Node Record (ENR), a signed record with your node's
public key, IP addresses and ports. Grandine logs the ENR at startup:

```text
ENR Initialised enr=enr:-… seq=1 id=… ip4=Some(203.0.113.10) udp4=Some(9000) tcp4=Some(9000) quic4=Some(9001) …
```

You can also read it, together with the peer ID and listening addresses, through the API:

```bash
curl -s http://127.0.0.1:5052/eth/v1/node/identity
```

The node's private key is stored in `network/key` in the data directory, and the last ENR in
`network/enr.dat`. The key determines the peer ID, so keep it if you want the same identity after a
reinstall. `--libp2p-private-key-file` loads the key from another file instead. The file holds a
hex-encoded secp256k1 private key, with or without `0x`.

### Public address

By default, Grandine learns its public IP address from its peers and updates the ENR when it
changes (`Address updated`, `Updated local ENR`). This works for most setups.

If the node sits behind NAT with a fixed public address, or you run it on a server with several
addresses, set the advertised values yourself:

```bash
grandine \
  --disable-upnp \
  --enr-address 203.0.113.10 \
  --enr-tcp-port 9000 \
  --enr-udp-port 9000 \
  --enr-quic-port 9001 \
  ...
```

`--disable-enr-auto-update` stops Grandine from changing the ENR address based on what peers
report.

If you do not set `--enr-tcp-port`, Grandine advertises the `--libp2p-port` in the ENR. Port values
in ENR options are only advertised: Grandine never opens sockets on them. Use them when an external
port differs from the local one, for example with port mapping on a router or in Docker.

## IPv6

Grandine listens on IPv4 only by default (`0.0.0.0`). To add IPv6, give an IPv6 listen address:

```bash
# Dual stack: IPv4 and IPv6
grandine --listen-address 0.0.0.0 --listen-address-ipv6 :: ...
```

IPv6 uses its own ports (9050 TCP and UDP, 9051 UDP for QUIC by default). Open them in the firewall
too. To advertise a specific IPv6 address, use `--enr-address-ipv6` and the `--enr-*-port-ipv6`
options.

For an IPv6-only node:

```bash
grandine --disable-ipv4 --listen-address-ipv6 :: ...
```

`--disable-ipv4` requires `--listen-address-ipv6` and cannot be combined with `--listen-address`,
`--enr-address`, `--enr-tcp-port`, `--enr-udp-port` or `--enr-quic-port`.

## Peers

### Target peer count

`--target-peers` (default: 200) is the number of peers Grandine aims for. Most log lines end with
the current count and the target:

```text
… peers=[87/200]
```

The count rises over the first minutes after startup. A higher target improves message
propagation and data availability but costs more bandwidth and CPU. On a slow connection, a lower
target such as 80 can help:

```bash
grandine --target-peers 80 ...
```

You can see the connected peers through the API:

```bash
curl -s http://127.0.0.1:5052/eth/v1/node/peer_count
curl -s http://127.0.0.1:5052/eth/v1/node/peers
```

### Boot nodes

Boot nodes are the first nodes Grandine contacts to discover the rest of the network. Each built-in
network comes with a list of boot nodes, so you do not need to configure anything.

`--boot-nodes` takes a comma-separated list of ENRs and **replaces** the built-in list:

```bash
grandine --network custom --boot-nodes enr:-AAA…,enr:-BBB… ...
```

For custom networks, Grandine reads the boot nodes from `bootstrap_nodes.txt` in the
`--configuration-directory` when `--boot-nodes` is not given. See
[Configuration files and custom networks](./configuration_files.md).

### Static peers and trusted peers

`--libp2p-nodes` takes a comma-separated list of multiaddresses that Grandine dials at startup:

```bash
grandine --libp2p-nodes /ip4/192.0.2.5/tcp/9000/p2p/16Uiu2HAm… ...
```

`--trusted-peers` takes a comma-separated list of peer IDs. Grandine treats these peers specially:

- they are never disconnected to make room for other peers,
- their peer score is not lowered, so they are not banned for misbehavior,
- they are explicit gossipsub peers, so Grandine always forwards gossip messages to them.

`--trusted-peers` does not dial the peers by itself. To keep a permanent link to a node you run,
give it both as a static peer and as a trusted peer:

```bash
grandine \
  --libp2p-nodes /ip4/192.0.2.5/tcp/9000/p2p/16Uiu2HAmPEER \
  --trusted-peers 16Uiu2HAmPEER \
  ...
```

Trusted peers are listed in the startup log (`trusted peers: [...]`). Keep the list short: every
trusted peer takes a slot that Grandine could otherwise fill with a well-behaved peer.

### Private networks

By default, discovery ignores peers that advertise private IP addresses (such as `192.168.x.x` or
`10.x.x.x`). For a local devnet or a network inside a LAN, enable `--enable-private-discovery`.

## Subnets

Attestations and sync committee messages are spread over subnets, and since Fulu, blob data is
spread over data column subnets. Grandine subscribes to the subnets its validators need, plus the
subnets the protocol requires of every node, and tries to keep at least `--target-subnet-peers`
(default: 3) peers on each subnet it uses.

- `--subscribe-all-subnets` subscribes to every attestation and sync committee subnet. This raises
  bandwidth and CPU use. It is useful for nodes that aggregate for many validators or serve
  external validator clients and relays. It does not include data column subnets.
- Data column subnets are covered by `--supernode` and `--semi-supernode`. See
  [PeerDAS and blob data](./peerdas.md).

## Peer scoring and rate limiting

Grandine scores its peers. Peers that send invalid data, break the protocol, or do not answer get
lower scores and are eventually disconnected and banned for a while. Gossipsub has its own scoring
on top. Both protect the node from spam and broken peers.

Grandine also limits how many requests it serves to, and sends to, each peer.

- `--disable-peer-scoring` turns peer scoring off. Use it only for testing.
- `--disable-rate-limiting` turns both inbound and outbound rate limiting off. Use it only for
  testing or private networks.

## Troubleshooting low peer count

If the peer count stays low (`peers=[5/200]` after half an hour), check:

1. **Ports.** Are TCP 9000, UDP 9000 and UDP 9001 open in the firewall and forwarded on the router?
   Check from outside, for example with an online port checker for TCP 9000.
2. **ENR.** Does `/eth/v1/node/identity` show your public IP address and the right ports? If not,
   set `--enr-address` and the ENR ports, and disable UPnP.
3. **Another instance.** Is another client already using the ports? Grandine refuses to start in
   that case, but a different client on another port may still compete for bandwidth.
4. **Clock.** Is the system clock in sync? Peers reject messages from nodes whose clocks are off.
5. **Network.** Are you on the network you think? Check `--network` and, for custom networks, the
   boot nodes.
6. **Bandwidth.** On a slow or metered connection, lower `--target-peers`.

See [Troubleshooting](./troubleshooting.md) for more.

## Command line options

See [Command line reference](./cli_options.md) for the full list.

- `--listen-address` (default: `0.0.0.0` unless `--disable-ipv4`): IPv4 listen address.
- `--listen-address-ipv6` (default: none): IPv6 listen address. Enables IPv6.
- `--disable-ipv4` (default: off): do not listen on IPv4. Requires `--listen-address-ipv6`.
- `--libp2p-port` (default: `9000`): libp2p TCP port, IPv4.
- `--libp2p-port-ipv6` (default: `9050`): libp2p TCP port, IPv6.
- `--discovery-port` (default: `9000`): discv5 UDP port, IPv4.
- `--discovery-port-ipv6` (default: `9050`): discv5 UDP port, IPv6.
- `--quic-port` (default: `9001`): QUIC UDP port, IPv4.
- `--quic-port-ipv6` (default: `9051`): QUIC UDP port, IPv6.
- `--disable-quic` (default: off): do not use QUIC.
- `--disable-upnp` (default: off): do not ask the router for port forwarding.
- `--enr-address`, `--enr-address-ipv6` (default: learned from peers): addresses to advertise.
- `--enr-tcp-port`, `--enr-udp-port`, `--enr-quic-port` and their `-ipv6` variants (default: the
  listening ports): ports to advertise.
- `--disable-enr-auto-update` (default: off): do not update the ENR address from peer reports.
- `--enable-private-discovery` (default: off): discover peers with private IP addresses.
- `--libp2p-private-key-file` (default: `network/key` in the data directory): node private key.
- `--network-dir` (default: `{data_dir}/{network}/network`): directory of the key and ENR.
- `--boot-nodes` (default: built-in list): comma-separated boot node ENRs. Replaces the built-in
  list.
- `--libp2p-nodes` (default: none): comma-separated multiaddresses to dial at startup.
- `--trusted-peers` (default: none): comma-separated peer IDs to always keep and never ban.
- `--target-peers` (default: `200`): target number of peers.
- `--target-subnet-peers` (default: `3`): target number of peers per subnet.
- `--subscribe-all-subnets` (default: off): subscribe to all attestation and sync committee
  subnets.
- `--disable-peer-scoring` (default: off): turn off peer scoring.
- `--disable-rate-limiting` (default: off): turn off inbound and outbound rate limiting.
