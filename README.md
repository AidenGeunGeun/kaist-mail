# kaist-mail

A terminal client for KAIST Dooray mail (`kaist.gov-dooray.com`) built for people and agents. It signs in through
KAIST SSO on its own, keeps a private session that renews itself, and prints compact JSON under `--json`. It reads
mail; it never sends, moves or deletes it.

## Install

On an Apple Silicon Mac:

```bash
curl -fsSL https://raw.githubusercontent.com/AidenGeunGeun/kaist-mail/main/scripts/install.sh | bash
```

The installer downloads the latest release, checks its SHA-256 and puts `kaist-mail` in `~/.local/bin`, with no
sudo. If that directory is not on your PATH it prints the line to add to `~/.zshrc`. Run it again to upgrade.
`KAIST_MAIL_VERSION=v0.1.0` picks a release and `KAIST_MAIL_INSTALL_DIR` another directory. Install with the script
rather than through a browser: macOS blocks a browser-downloaded binary because it is not notarized.

On an Intel Mac, or from source with Rust: `make build`, then copy `target/release/kaist-mail` onto your PATH.

## Quick start

Sign in with `kaist-mail auth login`: enter your KAIST ID and approve the number shown in the KAIST app (Easy Login).
The CLI remembers your ID and method.

When Dooray drops the session, the next command renews it once without your phone: first from the saved KAIST SSO
session, then, if you opted in, with a password kept in the macOS keychain
(`kaist-mail auth login --method password --remember-password`). When neither works, commands fail with
`AUTH_EXPIRED` and you run `kaist-mail auth login` again. `kaist-mail auth status` shows where you stand.

```bash
kaist-mail folders                          # every folder with unread and total counts
kaist-mail list --unread                    # newest unread inbox mail, 20 at a time
kaist-mail search --from 학사팀 --since 2026-09-01
kaist-mail read ID                          # one message as text (marks it read)
kaist-mail download ID --out ~/Downloads    # its attachments
```

Add `--json` before the command for agent-friendly output. `kaist-mail --help` is the full manual: workflow, JSON
contract, exit codes and safety.

## Development

`make check` runs fmt, tests, clippy and cargo-deny. `make smoke` packages the release archive and checks it offline
with the installer in an isolated HOME. See [AGENTS.md](AGENTS.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
and [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Acknowledgements

kaist-mail is inspired by [alazarteka/klms](https://github.com/alazarteka/klms), the KAIST KLMS CLI. Its
architecture, KAIST SSO handling, session storage and JSON contract follow klms, and portions of its code are
adapted from it.

## License

MIT. See LICENSE, which also carries the klms notice for the adapted portions.
