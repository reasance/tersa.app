# ADR 0016: Gmail REST mailbox adapter

- Status: Accepted
- Amended by: [ADR 0031](adr-0031-tui-only-pivot.md): portable adapter for macOS and Linux
- Date: 2026-07-16

## Context

The application mailbox port needs a portable production adapter without making
the application or domain depend on a networking runtime or Gmail DTOs.

## Decision

`tersa-gmail-rest` implements the existing `RemoteMailbox` port. It is
read-only and uses only authenticated `GET` requests below the fixed production
base `https://gmail.googleapis.com/gmail/v1/users/me`. It lists message IDs,
then hydrates them sequentially with metadata requests, preserving the provider
order. A message can be deleted after it appears in `messages.list`; a 404 from
that hydration request is skipped, while every other hydration failure fails the
page.

A page containing more messages than its requested `maxResults` is invalid and
is rejected before hydration. Provider-neutral message identifiers equal to
`.` or `..` are also rejected before transport because URL path-segment APIs
normalize those reserved values and would target the wrong resource.

Each adapter instance is bound to one opaque local `AccountId` before any I/O.
A different account returns `AuthorizationRequired`; Gmail's `users/me` result
cannot therefore be attributed to another local account. The constructor
immediately wraps a short-lived access token in `Zeroizing` before validation.
Rotation is performed by replacing the adapter. The mailbox adapter itself
performs no token exchange, refresh, persistence, Keychain access, retries,
batching, history sync, checkpointing, or logging.

The crate additionally hosts the ADR 0023 token transport as a distinct
component. `GmailTokenTransport` implements the application `TokenTransport`
port with form-encoded `POST` exchanges against Google's OAuth2 token endpoint,
plus a best-effort revoke call against the revoke endpoint. It shares only the
hardened reqwest client policy with the `GET` path — not the Gmail base URL,
the account binding, or any state — bounds token responses to 64 KiB, and
applies the same provider-data-free error discipline: token-endpoint request
and response bodies are never logged, and the form request body, the assembled
response buffer, and the parsed tokens are each held in `Zeroizing` memory or
wiped after use. Residue a zeroizing allocator would be needed to remove —
reqwest's own internal request/response buffers, and any intermediate
allocation freed while these buffers grew — is unavoidable, as on the `GET`
path. `GmailMailbox` remains `GET`-only.

Metadata requests use a partial response selector and select only `From` and
`Subject` headers. Missing singleton headers are represented by an empty
`HeaderText`; duplicate case-insensitive
singleton headers are invalid. Raw fetches verify the requested message and
thread identity across metadata and raw responses, accept padded or unpadded
base64url raw data, and return only decoded RFC 5322 bytes as `MessageContent`.
Label changes are tolerated. All DTO strings, JSON bodies, encoded raw input,
and decoded data are bounded. Errors are deliberately provider-data-free.

The reqwest client is HTTPS-only, has redirects and proxies
disabled, uses bounded timeouts, and does not compile cookie, decompression, or
multipart features. Response data is checked while it is accumulated; a
content-length is only an early rejection hint. Only bounded 403 error JSON is
read; bodies for statuses whose mapping is body-independent are discarded.

## Consequences

`reqwest` is exact-pinned in the manifests and owned by this adapter. Shared
layers remain runtime-free at the mailbox boundary. Platform TLS and crypto
choices are defined by ADR 0031.

## References

- [ADR 0023: Step 3 OAuth and bounded sync](adr-0023-step3-oauth-and-bounded-sync.md)
- [Gmail messages.list](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/list)
- [Gmail messages.get](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/get)
- [Gmail Message resource](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages#Message)
