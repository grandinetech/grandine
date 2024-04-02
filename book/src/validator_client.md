## Validator client

The Validator Client is a built-in component that is activated if validator keys are passed to Grandine. Let's try running Grandine with a new validator enabled on the Goerli network (assuming you already have keys, secrets etc.):

```
docker run                                                          \ 
  -p 9000:9000/tcp                                                  \
  -p 9000:9000/udp                                                  \
  -v $HOME/.grandine:/root/.grandine                                \
  -v $HOME/.grandine/jwtsecret:/root/.grandine/jwtsecret            \
  -v $HOME/.grandine/validator_keys:/root/.grandine/validator_keys  \
  -v $HOME/.grandine/secrets:/root/.grandine/secrets                \
  sifrai/grandine:unstable grandine                                 \
  --eth1-rpc-urls ETH1-RPC-URL                                      \
  --network goerli                                                  \
  --keystore-dir /root/.grandine/validator_keys                     \
  --keystore-password-file /root/.grandine/secrets
  --jwtsecret /root/.grandine/jwtsecret
```

In this example, the same secret is used to secure all the keystores, this secret should be placed in `$HOME/.grandine/secrets` file. Otherwise, for every keystore file in `$HOME/.grandine/validator_keys` there should be a corresponding file in the `$HOME/.grandine/secrets` directory with the secret file named the same as the corresponding keystore file except the extension should be `.txt` instead of `.json`.

For any sensitive keys it's a must to use a remote signer.

### Relevant command line options:

* `--keystore-dir` - a directory containing validator keystore files; 
* `--keystore-password-file` - a file containing a single secret for all the validator keystore files (this option usable if all the keystores are secured with the same secret);
* `--keystore-password-dir` - a directory containing secrets for all the validator keystore files (this option usable if all the keystores are secured with not the same secret), for every keystore file in `--keystore-dir` there should be a corresponding file in the `--keystore-password-dir` directory with the secret file named the same as the corresponding keystore file except the extension should be `.txt` instead of `.json`.
