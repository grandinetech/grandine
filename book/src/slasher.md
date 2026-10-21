# Slasher

A slasher watches the blocks and attestations on the network for slashable offenses: a validator
that proposes two different blocks for the same slot, or that casts a double vote or a surround
vote. When it finds one, it builds a proposer slashing or attester slashing so that a block
proposer can include it. Running a slasher protects the network. It does not protect your own
validators: that is the job of [slashing protection](./slashing_protection.md).

> **Warning:** Grandine's slasher is not available in current releases.
