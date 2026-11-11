# kaist-mail

A terminal client for KAIST Dooray mail (`kaist.gov-dooray.com`) built for people and agents. It signs in through
KAIST SSO on its own, keeps a private session, and prints compact JSON under `--json`.

```bash
cargo build --release --locked
target/release/kaist-mail auth login        # Easy Login: confirm the number in the KAIST app
target/release/kaist-mail --json folders
target/release/kaist-mail --json auth status
```

`kaist-mail --help` is the manual: workflow, JSON contract, exit codes and safety. `kaist-mail auth login --help`
covers password login, the two-step `--code` flow for agents, and keychain storage.

## Development

`make check` runs fmt, tests, clippy and cargo-deny. See [AGENTS.md](AGENTS.md),
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/PROTOCOL.md](docs/PROTOCOL.md).

## License

MIT. Portions are derived from [klms](https://github.com/alazarteka/klms); see LICENSE.
