# kaist-mail

A CLI for KAIST Dooray mail (`kaist.gov-dooray.com`), modeled on the KLMS CLI
(https://github.com/alazarteka/klms).

Progress and open questions: `docs/status.md`. Dooray endpoints and their behavior: `docs/PROTOCOL.md`.

## Requirements

- Work for English and Korean accounts alike, as klms does: key logic on stable identifiers, recognize both locales' labels
  and messages, and keep non-ASCII text (search terms, folder names, attachment filenames, message charsets) intact.
- Keep agent-facing output token-efficient; the mailbox has 999+ unread messages.

## Code and checks

- Toolchain pinned in `rust-toolchain.toml`; exact `=` dependency pins; `Cargo.lock` committed; `unsafe_code` forbidden.
- Run `make check` before finishing (fmt, `cargo test --locked --all-targets`, clippy `-D warnings`, cargo-deny).
- Module map: `docs/ARCHITECTURE.md`. `kaist-mail --help` is the user and agent manual; keep it accurate.
- Tests use loopback fixture servers and synthetic data only. Never commit real cookies, mail, or account ids.
- Never put real mail content (subjects, senders, bodies, attachment names) into transcripts or files; reduce live
  responses to shapes, counts and ids. Never derive `Debug` on types holding secrets.
- Agents never submit credentials or trigger Easy Login/OTP; ask the user to run `kaist-mail auth login`.

## Delegation

- Run every `general` subagent with `model: "anthropic-2/claude-opus-5-5#high"`. Never use `anthropic-1` for generals.
