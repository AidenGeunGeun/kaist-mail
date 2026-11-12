# Dooray mail web API

What `kaist.gov-dooray.com` serves to its mail web app, as kaist-mail uses it. The API is undocumented;
facts below were observed against a live account in November 2026 unless marked *(bundle)*, meaning
read from the web app's JavaScript. Dooray's public REST API (`dooray-api` tokens) has no mail
endpoints, so the CLI uses these web endpoints.

## Transport

- Base `https://kaist.gov-dooray.com`. The `SESSION` cookie alone authenticates every call below
  (`Domain=gov-dooray.com; Path=/; Secure; HttpOnly`, no expiry; the server enforces an idle timeout of
  unknown length). There is no CSRF token.
- Send `Accept: application/json, text/plain, */*`, `Dooray-Caller: WEB`, `Dooray-Api-Version: 1.1`,
  `Dooray-Mail-Api-Version: 1.2`. Version 1.2 reports truncated recipient lists as `toMore`/`ccMore`/`bccMore`.
- gzip is honoured. Responses over a few MB are slow (a 9 MB EML took about 49 s); stream downloads
  with long timeouts and keep list pages at 100 items or fewer.
- `members/me` `sessionCheckedAt` moves with interactive calls but not with `Dooray-User-Interaction: false`; Dooray
  exposes no remaining session time. An anonymous `SESSION` survived 50 min idle.
- Signed out or expired: wapi returns 401 with an empty body; `/mails/*/parts` returns 401 `text/html`;
  page routes 302 to `/auth/signin`.

## Envelope and errors

- Success: `{"header":{"resultCode":0,"isSuccessful":true,"resultMessage":""},"result":{...}}`.
- Business errors are HTTP 200 with `isSuccessful:false`, a negative integer `resultCode`, `result:null`, and a
  `resultMessage` localized to the account locale. Seen: `-100207` mail deleted or not found, `-200200` invalid
  request, `-200100` empty `mailIdList`, `-100300` server error, `-13207002` search keyword too long.
  kaist-mail shows only `resultCode`: `resultMessage` can quote request or mail data.
- An unknown path returns 404 with a Spring error body. No rate-limit headers appeared at 2-3 requests/s.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/v2/wapi/mail-folders?type=system\|user&size=10000&page=0` | folders with counts |
| GET | `/v2/wapi/members/me/counts/mail` | `result.content.counts.folders.<name>.{unread,total}` |
| GET | `/v2/wapi/mails/total-counts?folderName=inbox[&read=false]` | `result.content`, one integer |
| GET | `/v2/wapi/mails?...` | list (below) |
| GET | `/v2/wapi/mails?threadMailId=<id>&preview=true&size=ALL` | messages of one thread |
| POST | `/v2/wapi/mails/search?preview=true\|false` | search (below) |
| GET | `/v2/wapi/mails/{id}?render=html[&charset=<label>]` | detail; marks the message read |
| GET | `/v2/wapi/mails/{id}?type=raw` | full EML; does not mark read |
| GET | `fileList[].downloadUrl` (`/mails/{id}/parts/{n}?type=raw&t=...`) | attachment bytes, from the site root |
| GET | `/mails/{id}/parts?type=zip` | all attachments as one zip *(bundle)* |
| GET | `/v2/wapi/members/me` | `locale` (`ko_KR`, `en_US`, `ja_JP`, `zh_CN`), `timezoneName` |
| POST | `/v2/wapi/mails/read` `{"mailIdList":[id]}` | mark read *(bundle)* |
| POST | `/v2/wapi/mails/unread` `{"mailIdList":[id]}` | mark unread |

Move, delete and send endpoints live in the same web-app module and are not mapped yet.

## Folders

- System folders are identified by `name` in {`inbox`, `sent`, `draft`, `archive`, `spam`, `trash`} with
  `type:"system"`; `name` does not change with locale. `id` is a per-account numeric string.
- Fields: `id`, `name`, `type`, `totalCount`, `unreadCount`, `subscribed`, `imapName`, `mimeSize` (digit string),
  `openedFlag`, `imapNoselectFlag`. User folders were not observed (the account has none); expect
  `parentFolderId` and `displayOrder` as well.

## Listing: `GET /v2/wapi/mails`

- Scope: `folderName` or `folderId`, or `exceptFolders=a,b`. Paging: `page` (0-based) and `size`. Pages of 1000 rows
  arrived truncated (about 2 MB) for list and search; 500 arrived whole but slowly (list 6-20 s, search 36 s).
  `order=-createdAt` (newest first) or `createdAt`. Pages are offsets, so mail arriving between calls shifts them.
  Order within a tied second was stable on repeat; kaist-mail does not rely on it.
- Filters: `read=false`, `favorited=true`, `hasAttachment=true`. There is no date filter; use search.
- `preview=true` fills `mailSummary.previewText` (up to about 200 characters).
- `excludeTotalCount=true` skips counting; `totalCount` is then page*size plus the number returned.
- `view=conversation` groups by thread; `view=timeline` lists messages.
- Item fields: `id` (19-digit string), `createdAt` (received, ISO 8601 with offset), `subject`, `fileCount`,
  `mailSummary.{sentAt, mimeSize, priority, previewText, flags}` where `flags` holds 21 booleans including `read`,
  `favorite`, `replied`, `forwarded`; `threadMail.{id, type, count, unreadCount}` with type `single`,
  `thread-member` or `thread-group`; `users.{from, to[], cc[], bcc[], replyTo[]}` each
  `{type:"emailUser", emailUser:{name|null, emailAddress}}`; `folderId`; `references.folderMap`.
- An item costs about 2.6 KB of JSON with preview on; project it down before output.

## Search: `POST /v2/wapi/mails/search`

- JSON body. Keyword arrays: `all`, `subjects`, `bodies`, `fileNames`, `fromList`, `toList`, `ccList`.
  Scope: `folderNames[]`, `folderIds[]`, `exceptFolders[]`. Filters: `seenFlag:false` (unread), `favoritedFlag`,
  `attachedFlag`. Dates: `since`, `before` (ISO 8601 with offset). Paging and order: `page`, `size`, `order`.
- Matching is server-side substring, case-insensitive for ASCII. Values within one field and across fields are ANDed.
- NFC-normalize keywords: the NFD form of a Hangul word matches nothing.
- Keywords of 100 or more characters fail with `-13207002`.
- `totalCount` caps at 2000 and pages past 2000 hits come back empty.
- Hits are ordered by `mailSummary.sentAt` (the Date header); `order:"-createdAt"` means that order and `"createdAt"`
  reverses it. Rows without `sentAt` sort by `createdAt`. `since` and `before` are both inclusive, on `sentAt`.
- kaist-mail continues past the 2000-hit cap by narrowing `before` to the last shown sent second; a live walk
  returned 8,774 hits with none repeated (2026-11-12).
- Response: `result.totalCount`, `contents[]` with `id`, `sentAt`, `matchedFiles[]`, and `references.mailMap`
  (id to the full list item). Read subjects and fields from `mailMap`; `contents[].subject` is a highlight form
  and `contents[].sentAt` is always the epoch. With no hits, `references` is absent.

## Detail and read state

- `GET /v2/wapi/mails/{id}` marks the message read on the server, whatever `render`, `charset` or
  `Dooray-User-Interaction` says. The response's `mail.flags.read` shows the state before the call.
- `?type=raw` (EML) and attachment downloads leave the read state unchanged.
- `body.mimeType` is always `text/html`. Plain text comes from converting that HTML, from `previewText`, or from the
  EML's `text/plain` part. JSON is UTF-8; the server decodes each message's MIME charset, and `?charset=euc-kr`
  re-decodes the body. When parsing EML, decode charsets (including EUC-KR/CP949) locally.
- Detail-only fields: `mail.messageId`, `rcptTo`, `internalMail`, `originMailId`, `fileList[]`, `relation`.

## Attachments

- `fileList[]` has 16 keys: `id`, `name` (UTF-8, NFC), `size`, `mimeType`, `extension`, `partNumber`, `downloadUrl`,
  `messagePartId`, `bigfile`, `driveLink`, `encrypted`, `deleted`, `deletedAt`, `forbiddenExtensionFlag`, `createdAt`,
  `toBeDeletedAt`. No `bigfile`, `driveLink` or `encrypted` attachment has been observed.
- `downloadUrl` is `/mails/{id}/parts/{n}?type=raw&t=...` from the site root: same-origin, no redirects, needs only
  `SESSION`, `Content-Length` equals `size`. `t` is not required; without `type=raw` the URL answers 400 HTML, and
  prefixing `/v2/wapi` returns error `-100300`.
- `Range` is ignored (200, full length, no `Accept-Ranges`), and `type=raw` ignores `Accept-Encoding: gzip`. The raw
  EML endpoint often ends transfers early, over HTTP/1.1 and HTTP/2 alike: up to 21 MB usually 11-65 KB short of
  `Content-Length`, 24-35 MB often at 65-84% of it; slow clients fail more, and a repeat can complete (about a quarter
  of attempts did on a ~100 KB/s link, 2026-11-12). Attachment parts completed every time, 13.9 MB included.
  `mailSummary.mimeSize` equals the EML's `Content-Length`.
- Take the filename from `fileList[].name`. `Content-Disposition` depends on the User-Agent and can omit the
  filename entirely for non-ASCII names.

## Identifiers that do not depend on locale

`resultCode`, system folder `name` and `type`, flags, `threadMail.type`, `mimeType`, and ids. Only
`resultMessage` and display labels follow the account locale.

## KAIST SSO

- The SSO session is `JSESSIONID` (host `sso.kaist.ac.kr`, `Path=/auth`, HttpOnly, no expiry); `WHATAP` and `SCOUTER`
  are monitoring cookies. An anonymous SSO session lapsed between 25 and 35 min idle.
- Dooray's SAML request lands on `/auth/kaist/user/saml/login/link/redirect`. Without an SSO session it redirects to
  `login/view`; with one it answers the SAMLResponse form, which is how kaist-mail renews.
- Password-step codes: `SS0001` signed in (trusted device), `SS0098` second factor needed, `SS0099` register device,
  `SS0004`/`SS0005`/`SS0006` password change required (first login, reset, too old). The page offers a
  `changeLater` deferral; kaist-mail does not use it.
