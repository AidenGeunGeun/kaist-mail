# Status

What kaist-mail can do now, what is proven live, and what comes next.

## Settled direction (Aiden, 2026-11-12)

- Rust, one crate, built to the KLMS CLI's architecture and quality.
- Read-only for now; command boundaries should allow send/move/delete later.
- Reading a message marks it read, as the web app does.
- Token-efficient agent output is a first-class requirement (inbox: about 8,300 messages, 2,800 unread).
- English and Korean accounts both work.
- Login needs the user's phone; the user runs `kaist-mail auth login`, agents never trigger it.

## Capabilities

| Capability | Built | Proven live |
|---|---|---|
| SAML login via KAIST SSO (Easy Login, password + code) | yes | no |
| Session storage, expiry detection | yes | no |
| `folders` | yes | no |
| list, search | no | no |
| read, attachments | no | no |

## Next

1. Land the milestone 1 audit fixes, then have the user run the live login and `folders`.
2. Round 2: query workflow (folders with counts, list, search, continuation) and reading workflow (text body,
   attachments, streamed downloads) in parallel worktrees; then workflow measurements on a synthetic large mailbox.

## Open questions

- Server idle timeout of the `SESSION` cookie.
- Whether the `t` parameter on attachment URLs is required.
- Shape of user folders and of mark-read/unread responses.
