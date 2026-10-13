## Subcommands

Grandine has a few helpful subcommands:

*  `bn` - Run only the beacon node, without a validator client (example: `grandine bn --network holesky`);
*  `vc` - Run only the validator client against remote beacon nodes (example: `grandine vc --beacon-node-urls http://localhost:5052`);
*  `export` - Export blocks and state to ssz files within slot range for debugging (example: `grandine export --from 0 --to 5`);
*  `replay` - Replay blocks within slot range (example: `grandine replay --from 0 --to 5`);
*  `interchange` - Import/export slashing protection interchange file (example: `grandine interchange import file.json`);
*  `help` - Print this message or the help of the given subcommand(s).

Options for `bn` and `vc` must be given after the command: `grandine vc --network hoodi ...`, not `grandine --network hoodi vc ...`. See [Validator Client](./validator_client.md#running-the-validator-client-separately) for details.
