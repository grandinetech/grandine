## Subcommands

Grandine has a few helpful subcommands:

*  `db-info` - Show information about database records (example: `grandine db-info --database sync`);
*  `db-stats` - Show `beacon_fork_choice` database element sizes (example: `grandine db-stats`);
*  `export` - Export blocks and state to ssz files within slot range for debugging (example: `grandine export --from 0 --to 5`);
*  `replay` - Replay blocks within slot range (example: `grandine replay --from 0 --to 5`);
*  `interchange` - Import/export slashing protection interchange file (example: `grandine interchange import file.json`);
*  `help` - Print this message or the help of the given subcommand(s).
