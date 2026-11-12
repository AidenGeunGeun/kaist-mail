# Status

What kaist-mail can do now, what is proven live, and what comes next.

## Settled direction (Aiden, 2026-11-12)

- Rust, one crate, built to the KLMS CLI's architecture and quality.
- Read-only for now; command boundaries should allow send/move/delete later.
- Reading a message marks it read, as the web app does.
- Token-efficient agent output is a first-class requirement: inboxes hold thousands of messages.
- English and Korean accounts both work.
- Login needs the user's phone; the user runs `kaist-mail auth login`, agents never trigger it.

## Capabilities

| Capability | Built | Proven live |
|---|---|---|
| SAML login via KAIST SSO (Easy Login) | yes | yes (2026-11-12) |
| SAML login via password + code | yes | no |
| Session storage (`SESSION` plus SSO jar), expiry detection | yes | storage yes |
| `folders` | yes | yes |
| Session renewal without the phone (SSO session, remembered password) | yes | no |
| `list`, `search` (thin rows, cursors past the 2000-hit cap) | yes | yes |
| `read` (bounded text, marks read), `download`, `export` (leaves unread) | yes | yes, small files |
| Release archive, checksum, `scripts/install.sh` (Apple Silicon) | yes | local smoke only; no release published |
| Large transfers (several MB) | yes: up to 5 whole attempts within --max-seconds | yes, EML to 30 MB, attachment 13.9 MB |

## Next

1. Live renewal, as three separate results: SSO-session replay (`auth renew` after a fresh login), automatic recovery
   when Dooray actually rejects an idle session (next day, after sleep), and password renewal (blocked until the
   account's password change, SS0006).
2. Agent workflow measurements on a synthetic large mailbox: task cost in commands, requests, bytes and tokens.
3. Tag `v0.1.0` once the workflow measurements land (the archive ships README.md).
4. IMAP: `imap.gov-dooray.com:993` answers, but Dooray says public institutions get no IMAP and KAIST closed
   Outlook/iOS Mail access in 2021. Waiting on the user to check Settings -> Mail -> IMAP in the web app.

## Open questions

- Idle timeouts: Dooray's signed-in `SESSION`, and KAIST SSO's signed-in `JSESSIONID` (anonymous: 25-35 min).
  `auth status` records `longest_idle_accepted` and `renewal` to bound them.
- Shape of user folders, and of `bigfile`/`driveLink`/`encrypted` attachments.
- Why Dooray's raw EML endpoint closes transfers early (attachment parts do not).
- A search from 2000-01-01 returned 5 of 6 archive messages; probably one without a sent date.
