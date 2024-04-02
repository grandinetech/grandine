## Slashing Protection

Grandine supports the [Slashing Protection Interchange Format](https://eips.ethereum.org/EIPS/eip-3076). It's a must to migrate slashing protection data if you are switching validators between clients or servers.

Import Slashing Protection history to Grandine:

```
./grandine --network goerli interchange export slashing_protection.json
```

Export Slashing Protection history from Grandine:

```
./grandine --network goerli interchange export slashing_protection.json
```

We highly recommend waiting for a few epochs before starting validators after migration.
