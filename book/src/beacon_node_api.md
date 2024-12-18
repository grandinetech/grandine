## Beacon Node API

Grandine supports standard [Beacon Node API](https://ethereum.github.io/beacon-APIs/). This API is extensively tested against other CL validator clients and other Beacon Node API consumers such as [Vouch](https://github.com/attestantio/vouch). API is enabled by default. An example of running Grandine Beacon Node with API enabled by default:

```
docker run                                                          \
  -p 9000:9000/tcp                                                  \
  -p 9000:9000/udp                                                  \
  -v $HOME/.grandine:/root/.grandine                                \
  -v $HOME/.grandine/jwtsecret:/root/.grandine/jwtsecret            \
  sifrai/grandine:unstable grandine                                 \
  --checkpoint-sync-url CHECKPOINT-SYNC-URL                         \
  --eth1-rpc-urls ETH1-RPC-URL                                      \
  --jwt-secret JWT-SECRET-PATH
```

### Relevant command line options:

* `--http-port` - sets API listen port (default: `5052`);
* `--http-address` - sets API listen address (default: `127.0.0.1`);
* `--timeout` - sets API timeout in milliseconds (default: `10000`).
