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
   discarded.
