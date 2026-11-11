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
| Session storage (`SESSION` only, no expiry), expiry detection | yes | storage yes |
| `folders` | yes | yes |
| Session renewal without the phone | no | no |
| `list`, `search` (thin rows, cursors past the 2000-hit cap) | yes | yes |
| `read` (bounded text, marks read), `download`, `export` (leaves unread) | yes | yes, small files |
| Large transfers (several MB) | partial: truncated transfers fail cleanly | no |

## Next

1. Session renewal without the phone (branch `session-renew`).
2. Retry for truncated large transfers; workflow measurements on a synthetic large mailbox.

## Open questions

- Server idle timeout of the `SESSION` cookie.
- Shape of user folders, and of `bigfile`/`driveLink`/`encrypted` attachments.
- Why Dooray closes large transfers early, and whether a whole-transfer retry completes them.
- A search from 2000-01-01 returned 5 of 6 archive messages; probably one without a sent date.
