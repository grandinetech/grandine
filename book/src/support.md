# Support

There are several ways to get help with Grandine. Pick the one that fits your question.

## Discord

The quickest way to reach the Grandine team and other operators is the
[Grandine Discord](https://discord.gg/H9XCdUSyZd). Join it to ask questions about setup, upgrades
and errors, and to hear about new releases.

When you ask for help, include your Grandine version (`grandine --version`), the network, how you
run Grandine (binary, Docker, systemd), and the relevant log lines. See
[Reporting a bug](./troubleshooting.md#reporting-a-bug) for what makes a report useful.

## GitHub issues

Report bugs and request features on
[GitHub issues](https://github.com/grandinetech/grandine/issues). Search the existing issues first;
your problem may already be known or fixed in a newer release. A good bug report includes:

- the Grandine version and how you installed it;
- the full command line or `--args-file` contents, with secrets removed;
- the execution client and its version;
- logs from startup and from around the time of the problem;
- what you expected to happen and what happened instead.

Release notes and binaries are on the
[GitHub releases page](https://github.com/grandinetech/grandine/releases).

## Security issues

Do not report security vulnerabilities in public GitHub issues or public Discord channels. Email the team at
[info@grandine.io](mailto:info@grandine.io) with a description of the issue and steps to reproduce
it, and wait for a reply before you disclose anything publicly.
<!-- TODO(verify): the repository has no SECURITY.md and GitHub private vulnerability reporting is disabled; confirm with the team that info@grandine.io (the address in the crate metadata) is the right address for vulnerability reports. -->

Published security audits of Grandine are in the
[`audit` directory](https://github.com/grandinetech/grandine/tree/develop/audit) of the repository.
See [Security best practices](./security.md).

## Commercial support

[Contact us](mailto:info@grandine.io) if you are interested in commercial support for Grandine and
related services.

## Contributing

If you want to fix a bug or improve this book yourself, see
[Contributing and development](./contributing.md).
