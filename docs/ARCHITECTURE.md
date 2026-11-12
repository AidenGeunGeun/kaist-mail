# Architecture

Where each responsibility lives in the crate. The JSON contract and exit codes are documented in `kaist-mail --help`;
Dooray endpoints are in [PROTOCOL.md](PROTOCOL.md).

## Modules

- `main`: parse, run, print, exit code. `cli`: clap grammar; its help text is the manual. `commands`: dispatch and
  result shaping.
- `auth/`:
  - `flow`: SAML entry, KAIST SSO steps keyed on result codes, and the `SAMLResponse` handoff.
  - `transport`: login transport limited to the Dooray and SSO origins; assertion submission is Dooray-only.
  - `cookies`: transient jar; `cookies::live` is the one expiry rule for restore, send and load.
  - `store`: `session.json`, `login.json`, pending login; 0600 files, atomic replace.
  - `secret`: macOS keychain (service `kaist-mail`) through `/usr/bin/security`, secrets on stdin.
  - `parse`: page structure only, never visible text.
- `client`: exact-origin wapi client. A 401 or a redirect to `/auth/signin` or `/idp/*` is `AUTH_EXPIRED`; the
  envelope header is checked before the result, and `isSuccessful:false` is `UPSTREAM_ERROR`.
- `query`: `list` and `search`. Cursors key on the last row's second and ids; every page is chosen from one Dooray response
  that holds the cursor's whole second, picking rows by second and id; search narrows `before` and reads page 0,
  passing the 2000-hit cap.
  `message`: Dooray list item to the thin row and human table. `time`: RFC 3339 and KST date bounds.
- `mail`: one message as an agent reads it: `MailId`, the detail fetch (marks read), headers, attachments, body
  window (NFC; `--find` starts it at the line holding the next match). `html_text`: HTML body to plain text (html2text with a decorator: quotes `> `, links `text <url>`, images
  `[alt]`).
- `download`: `download` (attachments) and `export` (raw EML) to new private files; filename sanitizing and
  caseless collision checks. `client/transfer`: streaming transfers under `--max-seconds`/`--stall-seconds` with
  exact-size checks, restarting a transfer Dooray cuts short (up to 5 attempts); one absolute deadline bounds every
  request, renewal step, keychain call and lock wait of the command. `private_fs::publish_new`: no-overwrite publication (hidden 0600 temporary, link or copy).
- `http`: one blocking transport with per-hop redirect policy, deadlines and bounded reads; a 307/308 never re-sends
  a body to another origin.
- `output`, `error`: the JSON envelope, terminal sanitization (control and bidi characters only), error codes.

## Sign-in

1. `GET /auth/signin` -> `/idp/init` -> `/idp/multi`; the SAML button URL is read from `__NEXT_DATA__`.
2. `GET /idp/login/saml` -> `sso.kaist.ac.kr/auth/kaist/user/saml/login/link/redirect?SAMLRequest=...`; SSO keeps
   the request in its `JSESSIONID` and shows `/auth/kaist/user/login/view`. Credentials are sent only when that page's
   `agt_id` is `kaist-prod-dooray`.
3. KAIST SSO password + code or Easy Login, the same calls klms makes with Dooray's agent id and link URL.
4. `GET /auth/kaist/user/saml/login/link/redirect` returns an auto-post form; it must POST a nonempty `SAMLResponse`
   to `https://kaist.gov-dooray.com/idp/login/saml/process`. There is no RelayState: Dooray keeps the return URL in
   its anonymous `SESSION`, which must survive the flow.
5. The new `SESSION` is saved only after `GET /v2/wapi/mail-folders?type=system` succeeds with it. SSO cookies are
   kept in a separate jar in `session.json` and sent only to `sso.kaist.ac.kr`.

## Renewal

`auth/renew`: on a Dooray 401, `Client::signed` renews once per command and resends the request. Renewal replays
the SAML request with the saved SSO session, then tries a remembered password with codes refused; it never starts
Easy Login or sends a code. `state/session.lock` serializes sign-in, renewal and logout. `state/password-hold.json`
gates every automatic password use: it is written before the password leaves and cleared only when KAIST accepts it,
so a refused, cut-off or code-requiring attempt is never repeated until the next explicit `auth login`.
`state/session.used` records the last accepted call.

## Benchmark

`bench/` sits outside the crate. `dooray.py` builds a seeded synthetic mailbox at real scale (8,343 inbox messages,
2,785 unread) and a loopback Dooray emulation from the test fixtures; `run.py` runs scripted agent workflows with
known answers through the release binary and reports commands, requests, wire bytes, o200k_base tokens and time.
Run `cargo build --release --locked && uv run bench/run.py [--latency-ms 300]`.
