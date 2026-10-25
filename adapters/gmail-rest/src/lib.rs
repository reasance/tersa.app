// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Provides a bounded, read-only Gmail REST implementation of `RemoteMailbox`
//! and a bounded `POST` transport for Google's OAuth 2 token endpoint.
//!
//! The mailbox adapter is deliberately limited to authenticated `GET` requests
//! against Gmail's `users/me` resource. It owns one locally assigned account
//! and a short-lived token. The token transport implements the
//! ADR-0023 `TokenTransport` port as form-encoded `POST` exchanges against the
//! OAuth 2 token endpoint, plus a best-effort revoke call. It shares the
//! hardened client policy with the `GET` path but no endpoint or state, and
//! `GmailMailbox` itself remains `GET`-only. The crate never persists or logs
//! credentials.

#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::fmt;
use std::pin::Pin;
use std::time::Duration;

use base64::Engine;
use serde::Deserialize;
use tersa_application::mailbox::{
    BoxFuture, Page, PageSize, PageToken, RemoteMailbox, RemoteMailboxError,
};
use tersa_application::oauth::GMAIL_READONLY_SCOPE;
use tersa_application::token::{
    ExchangeRequest, IdTokenClaims, RefreshRequest, TokenResponse, TokenTransport,
    TokenTransportError,
};
use tersa_domain::mailbox::{
    AccountId, HeaderText, Message, MessageContent, MessageEnvelope, MessageId, ThreadId,
    UnixTimestampMillis,
};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

const BASE_URL: &str = "https://gmail.googleapis.com/gmail/v1/users/me";
const JSON_LIMIT: usize = 2 * 1024 * 1024;
const RAW_ENCODED_LIMIT: usize = MessageContent::MAX_LEN.div_ceil(3) * 4;
const RAW_JSON_OVERHEAD: usize = 4 * 1024;
const RAW_JSON_LIMIT: usize = RAW_ENCODED_LIMIT + RAW_JSON_OVERHEAD;
const METADATA_FIELDS: &str = "id,threadId,internalDate,labelIds,snippet,payload(headers)";
const RAW_FIELDS: &str = "id,threadId,raw";
const MAX_ACCESS_TOKEN_LEN: usize = 16 * 1024;
const CONNECT_TIMEOUT_SECS: u64 = 10;
/// Bounds one token-endpoint request, so it is the largest term of the connect
/// flow's cancellation latency.
const REQUEST_TIMEOUT_SECS: u64 = 30;
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const REVOKE_ENDPOINT: &str = "https://oauth2.googleapis.com/revoke";
const TOKEN_RESPONSE_LIMIT: usize = 64 * 1024;

type TransportFuture<'a> =
    Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + 'a>>;

/// Reads Gmail messages for one locally assigned account.
pub struct GmailMailbox {
    account: AccountId,
    transport: Box<dyn Transport>,
}

impl fmt::Debug for GmailMailbox {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GmailMailbox([REDACTED])")
    }
}

impl GmailMailbox {
    /// Creates a Gmail adapter with a short-lived access token for `account`.
    ///
    /// Replacing a rotated token requires replacing this adapter. The token is
    /// retained only in zeroizing memory and is never included in diagnostics.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteMailboxError::AuthorizationRequired`] for an empty,
    /// oversized, or control-character-containing token. Client construction
    /// failures return [`RemoteMailboxError::Transport`].
    pub fn new(account: AccountId, access_token: String) -> Result<Self, RemoteMailboxError> {
        let access_token = Zeroizing::new(access_token);
        validate_access_token(&access_token)?;
        Ok(Self {
            account,
            transport: Box::new(ReqwestTransport::new(access_token)?),
        })
    }

    #[cfg(test)]
    fn with_transport(account: AccountId, transport: impl Transport + 'static) -> Self {
        Self {
            account,
            transport: Box::new(transport),
        }
    }

    fn checked_account(&self, account: &AccountId) -> Result<(), RemoteMailboxError> {
        (self.account == *account)
            .then_some(())
            .ok_or(RemoteMailboxError::AuthorizationRequired)
    }

    async fn request_json<T: for<'de> Deserialize<'de>>(
        &self,
        request: Request,
        limit: usize,
    ) -> Result<T, RemoteMailboxError> {
        let body = self.request_body(request, limit).await?;
        serde_json::from_slice(&body).map_err(|_error| RemoteMailboxError::InvalidResponse)
    }

    /// The successful response body of `request`, unparsed.
    async fn request_body(
        &self,
        request: Request,
        limit: usize,
    ) -> Result<Vec<u8>, RemoteMailboxError> {
        let response = self
            .transport
            .get(request, limit)
            .await
            .map_err(TransportError::into_mailbox_error)?;
        if !(200..300).contains(&response.status) {
            return Err(map_status(response.status, &response.body));
        }
        Ok(response.body)
    }

    async fn metadata(&self, id: &MessageId) -> Result<GmailMetadata, RemoteMailboxError> {
        self.request_json(message_request(id, MessageFormat::Metadata)?, JSON_LIMIT)
            .await
    }
}

impl RemoteMailbox for GmailMailbox {
    fn list_recent_envelopes<'a>(
        &'a self,
        account: &'a AccountId,
        size: PageSize,
        page_token: Option<&'a PageToken>,
    ) -> BoxFuture<'a, Result<Page<MessageEnvelope>, RemoteMailboxError>> {
        Box::pin(async move {
            self.checked_account(account)?;
            let list: GmailList = self
                .request_json(list_request(size, page_token)?, JSON_LIMIT)
                .await?;
            if list.messages.len() > usize::from(size.get()) {
                return Err(RemoteMailboxError::InvalidResponse);
            }
            let next = list
                .next_page_token
                .map(PageToken::new)
                .transpose()
                .map_err(|_error| RemoteMailboxError::InvalidResponse)?;
            let mut envelopes = Vec::with_capacity(list.messages.len());
            for listed in list.messages {
                let id = MessageId::new(listed.id)
                    .map_err(|_error| RemoteMailboxError::InvalidResponse)?;
                let listed_thread = ThreadId::new(listed.thread_id)
                    .map_err(|_error| RemoteMailboxError::InvalidResponse)?;
                match self.metadata(&id).await {
                    Ok(metadata) => {
                        let envelope = envelope_from(metadata, &id)?;
                        if envelope.thread_id() != &listed_thread {
                            return Err(RemoteMailboxError::InvalidResponse);
                        }
                        envelopes.push(envelope);
                    }
                    Err(RemoteMailboxError::NotFound) => {
                        // Gmail may delete a listed message before hydration.
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(Page::new(envelopes, next))
        })
    }

    fn fetch_message<'a>(
        &'a self,
        account: &'a AccountId,
        message_id: &'a MessageId,
    ) -> BoxFuture<'a, Result<Message, RemoteMailboxError>> {
        Box::pin(async move {
            self.checked_account(account)?;
            let envelope = envelope_from(self.metadata(message_id).await?, message_id)?;
            let body = self
                .request_body(
                    message_request(message_id, MessageFormat::Raw)?,
                    RAW_JSON_LIMIT,
                )
                .await?;
            let content = {
                let raw: GmailRaw<'_> = serde_json::from_slice(&body)
                    .map_err(|_error| RemoteMailboxError::InvalidResponse)?;
                if raw.id != message_id.as_str() || raw.thread_id != envelope.thread_id().as_str() {
                    return Err(RemoteMailboxError::InvalidResponse);
                }
                decode_raw_with_limit(&raw.raw, MessageContent::MAX_LEN)?
            };
            drop(body);
            MessageContent::new(content)
                .map_err(|_error| RemoteMailboxError::InvalidResponse)
                .map(|content| Message::new(envelope, content))
        })
    }
}

trait Transport: Send + Sync {
    fn get(&self, request: Request, response_limit: usize) -> TransportFuture<'_>;
}

struct Request {
    url: Url,
}

impl Request {
    fn new(
        mut url: Url,
        segments: &[&str],
        query: &[(&str, String)],
    ) -> Result<Self, RemoteMailboxError> {
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|()| RemoteMailboxError::InvalidResponse)?;
            path.pop_if_empty();
            path.extend(segments);
        }
        url.query_pairs_mut()
            .extend_pairs(query.iter().map(|(key, value)| (*key, value.as_str())));
        Ok(Self { url })
    }
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

enum TransportError {
    Network,
    InvalidResponse,
}

impl TransportError {
    const fn into_mailbox_error(self) -> RemoteMailboxError {
        match self {
            Self::Network => RemoteMailboxError::Transport,
            Self::InvalidResponse => RemoteMailboxError::InvalidResponse,
        }
    }

    const fn into_token_error(self) -> TokenTransportError {
        match self {
            Self::Network => TokenTransportError::Transport,
            Self::InvalidResponse => TokenTransportError::MalformedResponse,
        }
    }
}

struct BoundedBody {
    bytes: Vec<u8>,
    limit: usize,
}

const fn body_limit(status: u16, success_limit: usize) -> usize {
    if status >= 200 && status < 300 {
        success_limit
    } else {
        JSON_LIMIT
    }
}

const fn reads_response_body(status: u16) -> bool {
    (status >= 200 && status < 300) || status == 403
}

impl BoundedBody {
    fn new(content_length: Option<usize>, limit: usize) -> Result<Self, TransportError> {
        if content_length.is_some_and(|length| length > limit) {
            return Err(TransportError::InvalidResponse);
        }
        Ok(Self {
            bytes: Vec::with_capacity(content_length.unwrap_or(0).min(limit)),
            limit,
        })
    }

    fn push(&mut self, chunk: &[u8]) -> Result<(), TransportError> {
        let next = self
            .bytes
            .len()
            .checked_add(chunk.len())
            .ok_or(TransportError::InvalidResponse)?;
        if next > self.limit {
            return Err(TransportError::InvalidResponse);
        }
        self.bytes.extend_from_slice(chunk);
        Ok(())
    }

    fn finish(mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

impl Drop for BoundedBody {
    fn drop(&mut self) {
        // Wipe any residue left in the accumulator — e.g. a partially streamed
        // token response abandoned on a network or overflow error. `finish`
        // takes the bytes out first, so a completed body is not owned here and a
        // successful caller wipes the returned buffer itself.
        self.bytes.zeroize();
    }
}

struct ReqwestTransport {
    client: reqwest::Client,
    token: Zeroizing<String>,
}

fn hardened_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(std::time::Duration::from_secs(CONNECT_TIMEOUT_SECS))
        .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .no_gzip()
        .no_brotli()
        .no_zstd()
}

impl ReqwestTransport {
    fn new(token: Zeroizing<String>) -> Result<Self, RemoteMailboxError> {
        let client = hardened_client_builder()
            .build()
            .map_err(|_error| RemoteMailboxError::Transport)?;
        Ok(Self { client, token })
    }
}

impl Transport for ReqwestTransport {
    fn get(&self, request: Request, response_limit: usize) -> TransportFuture<'_> {
        Box::pin(async move {
            let mut response = self
                .client
                .get(request.url)
                .bearer_auth(&*self.token)
                .send()
                .await
                .map_err(|_error| TransportError::Network)?;
            let status = response.status().as_u16();
            if !reads_response_body(status) {
                return Ok(HttpResponse {
                    status,
                    body: Vec::new(),
                });
            }
            let content_length = response
                .content_length()
                .and_then(|length| usize::try_from(length).ok());
            let mut body = BoundedBody::new(content_length, body_limit(status, response_limit))?;
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_error| TransportError::Network)?
            {
                body.push(&chunk)?;
            }
            Ok(HttpResponse {
                status,
                body: body.finish(),
            })
        })
    }
}

fn validate_access_token(token: &str) -> Result<(), RemoteMailboxError> {
    if token.is_empty() || token.len() > MAX_ACCESS_TOKEN_LEN || token.chars().any(char::is_control)
    {
        return Err(RemoteMailboxError::AuthorizationRequired);
    }
    Ok(())
}

fn list_request(size: PageSize, token: Option<&PageToken>) -> Result<Request, RemoteMailboxError> {
    let mut query = vec![
        ("maxResults", size.get().to_string()),
        ("fields", "messages(id,threadId),nextPageToken".to_owned()),
    ];
    if let Some(token) = token {
        query.push(("pageToken", token.as_str().to_owned()));
    }
    Request::new(
        Url::parse(BASE_URL).map_err(|_error| RemoteMailboxError::InvalidResponse)?,
        &["messages"],
        &query,
    )
}

#[derive(Clone, Copy)]
enum MessageFormat {
    Metadata,
    Raw,
}

fn message_request(id: &MessageId, format: MessageFormat) -> Result<Request, RemoteMailboxError> {
    if matches!(id.as_str(), "." | "..") {
        return Err(RemoteMailboxError::InvalidResponse);
    }
    let query = match format {
        MessageFormat::Metadata => vec![
            ("format", "metadata".to_owned()),
            ("metadataHeaders", "From".to_owned()),
            ("metadataHeaders", "Subject".to_owned()),
            ("fields", METADATA_FIELDS.to_owned()),
        ],
        MessageFormat::Raw => vec![
            ("format", "raw".to_owned()),
            ("fields", RAW_FIELDS.to_owned()),
        ],
    };
    Request::new(
        Url::parse(BASE_URL).map_err(|_error| RemoteMailboxError::InvalidResponse)?,
        &["messages", id.as_str()],
        &query,
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GmailList {
    #[serde(default)]
    messages: Vec<ListedMessage>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListedMessage {
    id: String,
    thread_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GmailMetadata {
    id: String,
    thread_id: String,
    internal_date: String,
    #[serde(default)]
    label_ids: Vec<String>,
    #[serde(default)]
    snippet: String,
    #[serde(default)]
    payload: Payload,
}

/// Borrows the base64 text from the response body: it has no JSON escapes,
/// so the largest field is never copied before it is decoded.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GmailRaw<'a> {
    id: String,
    thread_id: String,
    #[serde(borrow)]
    raw: Cow<'a, str>,
}

#[derive(Default, Deserialize)]
struct Payload {
    #[serde(default)]
    headers: Vec<Header>,
}

#[derive(Deserialize)]
struct Header {
    name: String,
    value: String,
}

fn envelope_from(
    message: GmailMetadata,
    expected_id: &MessageId,
) -> Result<MessageEnvelope, RemoteMailboxError> {
    if message.id != expected_id.as_str() {
        return Err(RemoteMailboxError::InvalidResponse);
    }
    let thread =
        ThreadId::new(message.thread_id).map_err(|_error| RemoteMailboxError::InvalidResponse)?;
    let timestamp = message
        .internal_date
        .parse::<i64>()
        .map_err(|_error| RemoteMailboxError::InvalidResponse)
        .and_then(|value| {
            UnixTimestampMillis::new(value).map_err(|_error| RemoteMailboxError::InvalidResponse)
        })?;
    let (from, subject) = headers(message.payload.headers)?;
    Ok(MessageEnvelope::new(
        expected_id.clone(),
        thread,
        HeaderText::new(from).map_err(|_error| RemoteMailboxError::InvalidResponse)?,
        HeaderText::new(subject).map_err(|_error| RemoteMailboxError::InvalidResponse)?,
        HeaderText::new(message.snippet).map_err(|_error| RemoteMailboxError::InvalidResponse)?,
        timestamp,
        message.label_ids.iter().any(|label| label == "UNREAD"),
    ))
}

fn headers(headers: Vec<Header>) -> Result<(String, String), RemoteMailboxError> {
    let mut from = None;
    let mut subject = None;
    for header in headers {
        if header.name.eq_ignore_ascii_case("from") {
            if from.replace(header.value).is_some() {
                return Err(RemoteMailboxError::InvalidResponse);
            }
        } else if header.name.eq_ignore_ascii_case("subject")
            && subject.replace(header.value).is_some()
        {
            return Err(RemoteMailboxError::InvalidResponse);
        }
    }
    Ok((from.unwrap_or_default(), subject.unwrap_or_default()))
}

fn decode_raw_with_limit(
    encoded: &str,
    decoded_limit: usize,
) -> Result<Vec<u8>, RemoteMailboxError> {
    let encoded_limit = decoded_limit
        .div_ceil(3)
        .checked_mul(4)
        .ok_or(RemoteMailboxError::InvalidResponse)?;
    if encoded.len() > encoded_limit {
        return Err(RemoteMailboxError::InvalidResponse);
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(encoded))
        .map_err(|_error| RemoteMailboxError::InvalidResponse)?;
    if decoded.len() > decoded_limit {
        return Err(RemoteMailboxError::InvalidResponse);
    }
    Ok(decoded)
}

fn map_status(status: u16, bytes: &[u8]) -> RemoteMailboxError {
    match status {
        401 => RemoteMailboxError::AuthorizationRequired,
        404 => RemoteMailboxError::NotFound,
        429 => RemoteMailboxError::RateLimited,
        500..=599 => RemoteMailboxError::Transport,
        403 => map_forbidden(bytes),
        _ => RemoteMailboxError::InvalidResponse,
    }
}

fn map_forbidden(bytes: &[u8]) -> RemoteMailboxError {
    let reasons = error_reasons(bytes);
    if reasons.iter().any(|reason| {
        matches!(
            reason.as_str(),
            "dailyLimitExceeded" | "rateLimitExceeded" | "userRateLimitExceeded" | "quotaExceeded"
        )
    }) {
        return RemoteMailboxError::RateLimited;
    }
    if reasons.iter().any(|reason| {
        matches!(
            reason.as_str(),
            "authError" | "insufficientPermissions" | "domainPolicy"
        )
    }) {
        return RemoteMailboxError::AuthorizationRequired;
    }
    RemoteMailboxError::InvalidResponse
}

fn error_reasons(bytes: &[u8]) -> Vec<String> {
    #[derive(Deserialize)]
    struct ErrorBody {
        error: ErrorDetail,
    }
    #[derive(Deserialize)]
    struct ErrorDetail {
        #[serde(default)]
        errors: Vec<ErrorReason>,
    }
    #[derive(Deserialize)]
    struct ErrorReason {
        reason: String,
    }
    serde_json::from_slice::<ErrorBody>(bytes)
        .map(|body| {
            body.error
                .errors
                .into_iter()
                .map(|error| error.reason)
                .collect()
        })
        .unwrap_or_default()
}

type PostFuture<'a> =
    Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + 'a>>;

/// Exchanges, refreshes, and revokes tokens against Google's OAuth 2 endpoints.
///
/// Implements the ADR-0023 [`TokenTransport`] port as form-encoded `POST`
/// requests to the token endpoint, sharing the hardened client policy with the
/// `GET` path but no endpoint or state. Request and response bodies carry
/// credentials, so they are never logged; the form request body, the assembled
/// response buffer, and the parsed tokens are each held in zeroizing memory or
/// wiped after use. Some residue is unavoidable without a zeroizing allocator:
/// reqwest's own request and response buffers, and any intermediate buffer
/// freed while a `Vec` or `String` grew during body assembly or form
/// encoding — as on the bearer-token `GET` path.
pub struct GmailTokenTransport {
    transport: Box<dyn PostTransport>,
}

impl fmt::Debug for GmailTokenTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GmailTokenTransport([REDACTED])")
    }
}

impl GmailTokenTransport {
    /// Creates a token transport with the hardened HTTP client.
    ///
    /// The transport is stateless beyond the client: each request carries its
    /// own client identity and secrets.
    ///
    /// # Errors
    ///
    /// Returns [`TokenTransportError::Transport`] when the hardened client
    /// cannot be constructed.
    pub fn new() -> Result<Self, TokenTransportError> {
        Ok(Self {
            transport: Box::new(ReqwestPostTransport::new()?),
        })
    }

    #[cfg(test)]
    fn with_transport(transport: impl PostTransport + 'static) -> Self {
        Self {
            transport: Box::new(transport),
        }
    }

    async fn post_token(
        &self,
        parameters: &[(&'static str, Zeroizing<String>)],
    ) -> Result<TokenResponse, TokenTransportError> {
        let response = self
            .transport
            .post(TOKEN_ENDPOINT, form_body(parameters))
            .await
            .map_err(TransportError::into_token_error)?;
        let mut body = response.body;
        let result = if response.status == 200 {
            parse_token_response(&body)
        } else {
            Err(map_error_response(&body))
        };
        // The assembled response buffer held the cleartext access and refresh
        // tokens (or an error body that can echo request parameters); wipe this
        // adapter-owned copy. Residue can still remain in reqwest's internal
        // buffers and in intermediate allocations freed while this buffer grew.
        body.zeroize();
        result
    }
}

impl TokenTransport for GmailTokenTransport {
    fn exchange(
        &self,
        request: ExchangeRequest,
    ) -> BoxFuture<'_, Result<TokenResponse, TokenTransportError>> {
        Box::pin(async move { self.post_token(&request.parameters()).await })
    }

    fn refresh(
        &self,
        request: RefreshRequest,
    ) -> BoxFuture<'_, Result<TokenResponse, TokenTransportError>> {
        Box::pin(async move { self.post_token(&request.parameters()).await })
    }

    /// Revokes a token at Google's revoke endpoint, best-effort.
    ///
    /// The token is sent as the single form-encoded `token` parameter. HTTP 200
    /// is success; a well-formed HTTP 400 `invalid_token` answer (Google's
    /// response for an unknown or already-revoked token) resolves to
    /// [`TokenTransportError::InvalidToken`] so the caller can confirm the
    /// desired end state; any other status, an unparsable error body, or a
    /// network failure resolves to a [`TokenTransportError`] without provider
    /// data.
    /// Account removal treats revocation as best-effort and still deletes the
    /// local token and data when this call fails, then tells the user how to
    /// revoke access manually.
    fn revoke<'a>(
        &'a self,
        token: &'a Zeroizing<String>,
    ) -> BoxFuture<'a, Result<(), TokenTransportError>> {
        Box::pin(async move {
            let response = self
                .transport
                .post(REVOKE_ENDPOINT, form_body(&[("token", token.clone())]))
                .await
                .map_err(TransportError::into_token_error)?;
            let mut body = response.body;
            let result = if response.status == 200 {
                Ok(())
            } else {
                Err(map_revoke_error_response(&body))
            };
            body.zeroize();
            result
        })
    }
}

trait PostTransport: Send + Sync {
    fn post(&self, endpoint: &'static str, form: Zeroizing<String>) -> PostFuture<'_>;
}

struct ReqwestPostTransport {
    client: reqwest::Client,
}

impl ReqwestPostTransport {
    fn new() -> Result<Self, TokenTransportError> {
        let client = hardened_client_builder()
            .build()
            .map_err(|_error| TokenTransportError::Transport)?;
        Ok(Self { client })
    }
}

impl PostTransport for ReqwestPostTransport {
    fn post(&self, endpoint: &'static str, form: Zeroizing<String>) -> PostFuture<'_> {
        Box::pin(async move {
            let mut response = self
                .client
                .post(endpoint)
                .header(
                    reqwest::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(form.to_string())
                .send()
                .await
                .map_err(|_error| TransportError::Network)?;
            drop(form);
            let status = response.status().as_u16();
            let content_length = response
                .content_length()
                .and_then(|length| usize::try_from(length).ok());
            let mut body = BoundedBody::new(content_length, TOKEN_RESPONSE_LIMIT)?;
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_error| TransportError::Network)?
            {
                body.push(&chunk)?;
            }
            Ok(HttpResponse {
                status,
                body: body.finish(),
            })
        })
    }
}

fn form_body(parameters: &[(&'static str, Zeroizing<String>)]) -> Zeroizing<String> {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in parameters {
        serializer.append_pair(name, value.as_str());
    }
    Zeroizing::new(serializer.finish())
}

fn deserialize_zeroizing<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // Land the secret directly in a zeroizing wrapper, so a parse error on a
    // later field drops it already wiped rather than as a plain `String`.
    Ok(Zeroizing::new(String::deserialize(deserializer)?))
}

fn deserialize_optional_zeroizing<'de, D>(
    deserializer: D,
) -> Result<Option<Zeroizing<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.map(Zeroizing::new))
}

fn parse_token_response(bytes: &[u8]) -> Result<TokenResponse, TokenTransportError> {
    #[derive(Deserialize)]
    #[expect(
        dead_code,
        reason = "the token type completes the provider response shape but carries no state the port retains"
    )]
    struct TokenResponseBody {
        #[serde(deserialize_with = "deserialize_zeroizing")]
        access_token: Zeroizing<String>,
        expires_in: u64,
        #[serde(default, deserialize_with = "deserialize_optional_zeroizing")]
        refresh_token: Option<Zeroizing<String>>,
        token_type: String,
        scope: Option<String>,
        #[serde(default, deserialize_with = "deserialize_optional_zeroizing")]
        id_token: Option<Zeroizing<String>>,
    }
    let parsed = serde_json::from_slice::<TokenResponseBody>(bytes)
        .map_err(|_error| TokenTransportError::MalformedResponse)?;
    let gmail_read_granted = parsed.scope.as_deref().is_none_or(|scope| {
        scope
            .split_ascii_whitespace()
            .any(|granted| granted == GMAIL_READONLY_SCOPE)
    });
    // Scope is the earlier security boundary: an explicitly under-scoped
    // response must reach lifecycle cleanup with its minted token handles even
    // when the same response carries a malformed id_token. Identity is never
    // consumed for a rejected scope, so parsing it here would only strand the
    // provider grant before the caller can revoke it.
    let id_token_claims = match (gmail_read_granted, parsed.id_token) {
        (true, Some(id_token)) => Some(parse_id_token_claims(id_token.as_str())?),
        (true, None) | (false, _) => None,
    };
    Ok(TokenResponse::new(
        parsed.access_token,
        Duration::from_secs(parsed.expires_in),
        parsed.refresh_token,
        id_token_claims,
        gmail_read_granted,
    ))
}

/// Decodes the identity claims from an `id_token` WITHOUT verifying its signature.
///
/// The signature is intentionally not checked: this is only ever called on an
/// `id_token` received in the token-endpoint response over the crate's hardened
/// TLS client, directly from the token endpoint — the TLS origin authenticates
/// the issuer (OIDC Core 3.1.3.7). This helper is deliberately private and its
/// sole caller is [`parse_token_response`]; it must NEVER be fed a token from a
/// front channel, cache, or IPC, where signature verification would be mandatory.
/// It performs only a STRUCTURAL decode — the semantic `aud`/`iss`/`sub` checks
/// live in the application layer, which holds the client identity as a typed value.
fn parse_id_token_claims(id_token: &str) -> Result<IdTokenClaims, TokenTransportError> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Audience {
        One(String),
        Many(Vec<String>),
    }

    #[derive(Deserialize)]
    struct IdTokenPayload {
        #[serde(deserialize_with = "deserialize_zeroizing")]
        sub: Zeroizing<String>,
        aud: Audience,
        iss: String,
        #[serde(default)]
        azp: Option<String>,
        // `iat`/`exp` are required OIDC claims: a token missing either is
        // structurally incomplete (MalformedResponse). Freshness is validated
        // later in the session against a wall clock.
        iat: u64,
        exp: u64,
    }

    // A Google id_token is a signed JWT: exactly header.payload.signature.
    let mut segments = id_token.split('.');
    let (Some(header), Some(payload), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(TokenTransportError::MalformedResponse);
    };
    // Require all three segments to be non-empty valid base64url — a structurally
    // complete compact JWS — even though the signature is not verified (the TLS
    // origin authenticates the issuer). This rejects a token with an empty or
    // malformed header/signature that only happens to carry a decodable payload.
    decode_b64url_segment(header)?;
    decode_b64url_segment(signature)?;
    let payload_bytes = decode_b64url_segment(payload)?;
    let payload = serde_json::from_slice::<IdTokenPayload>(&payload_bytes)
        .map_err(|_error| TokenTransportError::MalformedResponse)?;
    let audiences = match payload.aud {
        Audience::One(audience) => vec![audience],
        Audience::Many(audiences) => audiences,
    };
    Ok(IdTokenClaims::new(
        payload.sub,
        audiences,
        payload.iss,
        payload.azp,
        payload.iat,
        payload.exp,
    ))
}

/// Decodes one non-empty base64url JWT segment into a zeroizing buffer.
///
/// Decoding into caller-owned zeroizing storage wipes any partially decoded
/// bytes on the error path too — `base64`'s own `decode` would drop its internal
/// buffer unzeroized, potentially leaving account-identifying `sub` residue.
fn decode_b64url_segment(segment: &str) -> Result<Zeroizing<Vec<u8>>, TokenTransportError> {
    if segment.is_empty() {
        return Err(TokenTransportError::MalformedResponse);
    }
    let mut buffer = Zeroizing::new(vec![0_u8; base64::decoded_len_estimate(segment.len())]);
    let written = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode_slice(segment, buffer.as_mut_slice())
        .map_err(|_error| TokenTransportError::MalformedResponse)?;
    buffer.truncate(written);
    Ok(buffer)
}

fn map_error_response(bytes: &[u8]) -> TokenTransportError {
    #[derive(Deserialize)]
    struct TokenErrorBody {
        error: String,
    }
    match serde_json::from_slice::<TokenErrorBody>(bytes) {
        Ok(body) if body.error == "invalid_grant" => TokenTransportError::InvalidGrant,
        Ok(_body) => TokenTransportError::ProviderRejected,
        Err(_error) => TokenTransportError::MalformedResponse,
    }
}

/// Maps a revoke-endpoint error body, keeping Google's `invalid_token` answer
/// distinct from a generic rejection.
///
/// Google's revoke endpoint answers HTTP 400 `invalid_token` when the submitted
/// token is unknown or already revoked: the desired end state (no usable grant)
/// already holds, so the caller must be able to confirm it. The token-endpoint
/// mapping above deliberately does NOT special-case `invalid_token` — Google
/// does not emit it for exchange or refresh, and if a provider ever did, the
/// conservative `ProviderRejected` answer must not change. Every other
/// well-formed revoke error matches the token-endpoint mapping.
fn map_revoke_error_response(bytes: &[u8]) -> TokenTransportError {
    #[derive(Deserialize)]
    struct RevokeErrorBody {
        error: String,
    }
    match serde_json::from_slice::<RevokeErrorBody>(bytes) {
        Ok(body) if body.error == "invalid_token" => TokenTransportError::InvalidToken,
        Ok(body) if body.error == "invalid_grant" => TokenTransportError::InvalidGrant,
        Ok(_body) => TokenTransportError::ProviderRejected,
        Err(_error) => TokenTransportError::MalformedResponse,
    }
}

// Rust guideline compliant 1.0.

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::future::pending;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::Duration;

    use tersa_application::mailbox::{PageSize, PageToken, RemoteMailbox, RemoteMailboxError};
    use tersa_application::oauth::{
        AuthorizationConfig, AuthorizationGrant, MonotonicClock, prepare_authorization,
    };
    use tersa_application::token::{
        ExchangeRequest, RefreshRequest, TokenClientConfig, TokenTransport, TokenTransportError,
        exchange_grant, refresh_access_token,
    };
    use tersa_domain::mailbox::{AccountId, MessageId};
    use zeroize::Zeroizing;

    use super::{
        BoundedBody, BoxFuture, GmailMailbox, GmailTokenTransport, HttpResponse, JSON_LIMIT,
        PostFuture, PostTransport, RAW_JSON_LIMIT, REVOKE_ENDPOINT, Request, TOKEN_ENDPOINT,
        TOKEN_RESPONSE_LIMIT, TokenResponse, Transport, TransportError, TransportFuture, Url,
        body_limit, decode_raw_with_limit, map_status, parse_id_token_claims, parse_token_response,
        reads_response_body,
    };

    const ACCOUNT: &str = "account-1";

    #[derive(Clone)]
    struct FakeTransport {
        state: Arc<FakeState>,
    }

    struct FakeState {
        replies: Mutex<VecDeque<Reply>>,
        requests: Mutex<Vec<(String, usize)>>,
    }

    enum Reply {
        Response {
            status: u16,
            content_length: Option<usize>,
            chunks: Vec<Vec<u8>>,
        },
        Network,
        Pending(Arc<AtomicBool>),
    }

    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    impl FakeTransport {
        fn new(replies: Vec<Reply>) -> Self {
            Self {
                state: Arc::new(FakeState {
                    replies: Mutex::new(replies.into()),
                    requests: Mutex::new(Vec::new()),
                }),
            }
        }

        fn requests(&self) -> Vec<(String, usize)> {
            self.state.requests.lock().map_or_else(
                |poisoned| poisoned.into_inner().clone(),
                |guard| guard.clone(),
            )
        }
    }

    impl Transport for FakeTransport {
        fn get(&self, request: Request, response_limit: usize) -> TransportFuture<'_> {
            self.state
                .requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((request.url.into(), response_limit));
            let reply = self
                .state
                .replies
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front();
            Box::pin(async move {
                match reply {
                    Some(Reply::Response {
                        status,
                        content_length,
                        chunks,
                    }) => {
                        if !reads_response_body(status) {
                            return Ok(HttpResponse {
                                status,
                                body: Vec::new(),
                            });
                        }
                        let mut body =
                            BoundedBody::new(content_length, body_limit(status, response_limit))?;
                        for chunk in chunks {
                            body.push(&chunk)?;
                        }
                        Ok(HttpResponse {
                            status,
                            body: body.finish(),
                        })
                    }
                    Some(Reply::Network) | None => Err(TransportError::Network),
                    Some(Reply::Pending(dropped)) => {
                        let _drop_signal = DropSignal(dropped);
                        pending::<()>().await;
                        unreachable!("pending fake transport completed")
                    }
                }
            })
        }
    }

    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    fn poll_once<T>(future: Pin<&mut dyn Future<Output = T>>) -> Poll<T> {
        let waker = Waker::from(Arc::new(NoopWake));
        future.poll(&mut Context::from_waker(&waker))
    }

    fn ready<T>(mut future: Pin<Box<dyn Future<Output = T> + Send + '_>>) -> T {
        match poll_once(future.as_mut()) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("test future unexpectedly remained pending"),
        }
    }

    fn account(value: &str) -> AccountId {
        AccountId::new(value).unwrap_or_else(|error| panic!("invalid test account: {error}"))
    }

    fn message_id(value: &str) -> MessageId {
        MessageId::new(value).unwrap_or_else(|error| panic!("invalid test message ID: {error}"))
    }

    fn json(status: u16, body: &str) -> Reply {
        Reply::Response {
            status,
            content_length: Some(body.len()),
            chunks: body.as_bytes().chunks(7).map(<[u8]>::to_vec).collect(),
        }
    }

    fn metadata(id: &str, thread: &str, unread: bool) -> String {
        let labels = if unread {
            r#"["UNREAD","INBOX"]"#
        } else {
            "[]"
        };
        format!(
            r#"{{"id":"{id}","threadId":"{thread}","internalDate":"42","labelIds":{labels},"snippet":"Preview","payload":{{"headers":[{{"name":"From","value":"Sender <sender@example.test>"}},{{"name":"Subject","value":"Subject"}}]}}}}"#
        )
    }

    #[derive(Clone)]
    struct FakePostTransport {
        state: Arc<FakePostState>,
    }

    struct FakePostState {
        replies: Mutex<VecDeque<Reply>>,
        requests: Mutex<Vec<(String, Zeroizing<String>)>>,
    }

    impl FakePostTransport {
        fn new(replies: Vec<Reply>) -> Self {
            Self {
                state: Arc::new(FakePostState {
                    replies: Mutex::new(replies.into()),
                    requests: Mutex::new(Vec::new()),
                }),
            }
        }

        fn requests(&self) -> Vec<(String, Zeroizing<String>)> {
            self.state.requests.lock().map_or_else(
                |poisoned| poisoned.into_inner().clone(),
                |guard| guard.clone(),
            )
        }
    }

    impl PostTransport for FakePostTransport {
        fn post(&self, endpoint: &'static str, form: Zeroizing<String>) -> PostFuture<'_> {
            self.state
                .requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((endpoint.to_owned(), form));
            let reply = self
                .state
                .replies
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front();
            Box::pin(async move {
                match reply {
                    Some(Reply::Response {
                        status,
                        content_length,
                        chunks,
                    }) => {
                        let mut body = BoundedBody::new(content_length, TOKEN_RESPONSE_LIMIT)?;
                        for chunk in chunks {
                            body.push(&chunk)?;
                        }
                        Ok(HttpResponse {
                            status,
                            body: body.finish(),
                        })
                    }
                    Some(Reply::Network) | None => Err(TransportError::Network),
                    Some(Reply::Pending(dropped)) => {
                        let _drop_signal = DropSignal(dropped);
                        pending::<()>().await;
                        unreachable!("pending fake transport completed")
                    }
                }
            })
        }
    }

    #[derive(Debug, Default)]
    struct RequestCapture {
        exchange: Mutex<Option<ExchangeRequest>>,
        refresh: Mutex<Option<RefreshRequest>>,
    }

    impl TokenTransport for RequestCapture {
        fn exchange(
            &self,
            request: ExchangeRequest,
        ) -> BoxFuture<'_, Result<TokenResponse, TokenTransportError>> {
            *self
                .exchange
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(request);
            Box::pin(async { Err(TokenTransportError::Transport) })
        }

        fn refresh(
            &self,
            request: RefreshRequest,
        ) -> BoxFuture<'_, Result<TokenResponse, TokenTransportError>> {
            *self
                .refresh
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(request);
            Box::pin(async { Err(TokenTransportError::Transport) })
        }

        fn revoke<'a>(
            &'a self,
            _token: &'a Zeroizing<String>,
        ) -> BoxFuture<'a, Result<(), TokenTransportError>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[derive(Clone, Debug, Default)]
    struct TestClock(Arc<AtomicU64>);

    impl MonotonicClock for TestClock {
        fn now(&self) -> Duration {
            Duration::from_secs(self.0.load(Ordering::Relaxed))
        }
    }

    fn test_redirect() -> Url {
        Url::parse("app.tersa.oauth.test:/oauth/callback")
            .unwrap_or_else(|error| panic!("invalid test redirect: {error}"))
    }

    fn make_config(client_secret: Option<&str>) -> TokenClientConfig {
        TokenClientConfig::new(
            "public-test-client",
            test_redirect(),
            client_secret.map(|secret| Zeroizing::new(secret.to_owned())),
        )
        .unwrap_or_else(|error| panic!("invalid test token configuration: {error}"))
    }

    fn make_grant(code: &str) -> AuthorizationGrant {
        let config = AuthorizationConfig::new(
            "public-test-client",
            test_redirect(),
            Duration::from_secs(60),
        )
        .unwrap_or_else(|error| panic!("invalid test authorization configuration: {error}"));
        let prepared = prepare_authorization(config, TestClock::default())
            .unwrap_or_else(|error| panic!("authorization preparation failed: {error}"));
        let state = prepared
            .authorization_url()
            .query_pairs()
            .find_map(|(name, value)| (name == "state").then(|| value.into_owned()))
            .unwrap_or_else(|| panic!("missing test state"));
        let mut callback = test_redirect();
        callback
            .query_pairs_mut()
            .append_pair("state", &state)
            .append_pair("code", code);
        let (_, mut session) = prepared.into_parts();
        session
            .finish(&callback)
            .unwrap_or_else(|error| panic!("test callback rejected: {error}"))
    }

    fn captured_exchange(client_secret: Option<&str>) -> (AuthorizationGrant, ExchangeRequest) {
        let grant = make_grant("exchange-code");
        let config = make_config(client_secret);
        let capture = RequestCapture::default();
        assert!(
            ready(exchange_grant(
                &grant,
                &config,
                &capture,
                &TestClock::default()
            ))
            .is_err()
        );
        let request = capture
            .exchange
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .unwrap_or_else(|| panic!("the exchange request was not captured"));
        (grant, request)
    }

    fn captured_refresh(client_secret: Option<&str>) -> RefreshRequest {
        let refresh_token = Zeroizing::new("stored-refresh-token".to_owned());
        let config = make_config(client_secret);
        let capture = RequestCapture::default();
        assert!(
            ready(refresh_access_token(
                &refresh_token,
                &config,
                &capture,
                &TestClock::default()
            ))
            .is_err()
        );
        capture
            .refresh
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .unwrap_or_else(|| panic!("the refresh request was not captured"))
    }

    fn token_success_body(rotated_refresh_token: Option<&str>) -> String {
        match rotated_refresh_token {
            Some(token) => format!(
                r#"{{"access_token":"fresh-access-token","expires_in":3599,"refresh_token":"{token}","scope":"https://www.googleapis.com/auth/gmail.readonly","token_type":"Bearer"}}"#
            ),
            None => r#"{"access_token":"fresh-access-token","expires_in":3599,"scope":"https://www.googleapis.com/auth/gmail.readonly","token_type":"Bearer"}"#.to_owned(),
        }
    }

    #[test]
    fn lists_in_provider_order_with_exact_requests_and_next_token() {
        let transport = FakeTransport::new(vec![
            json(
                200,
                r#"{"messages":[{"id":"m1","threadId":"t1"},{"id":"m2","threadId":"t2"}],"nextPageToken":"next/token"}"#,
            ),
            json(200, &metadata("m1", "t1", true)),
            json(200, &metadata("m2", "t2", false)),
        ]);
        let mailbox = GmailMailbox::with_transport(account(ACCOUNT), transport.clone());
        let page_token = PageToken::new("page/token").unwrap_or_else(|error| panic!("{error}"));
        let result = ready(mailbox.list_recent_envelopes(
            &account(ACCOUNT),
            PageSize::new(2).unwrap_or_else(|error| panic!("{error}")),
            Some(&page_token),
        ))
        .unwrap_or_else(|error| panic!("list failed: {error}"));

        assert_eq!(result.items().len(), 2);
        assert_eq!(result.items()[0].message_id().as_str(), "m1");
        assert!(result.items()[0].is_unread());
        assert_eq!(result.items()[1].message_id().as_str(), "m2");
        assert!(!result.items()[1].is_unread());
        assert_eq!(
            result.next_token().map(PageToken::as_str),
            Some("next/token")
        );

        let requests = transport.requests();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].1, JSON_LIMIT);
        assert_eq!(requests[1].1, JSON_LIMIT);
        assert_eq!(
            requests[0].0,
            "https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=2&fields=messages%28id%2CthreadId%29%2CnextPageToken&pageToken=page%2Ftoken"
        );
        assert_eq!(
            requests[1].0,
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/m1?format=metadata&metadataHeaders=From&metadataHeaders=Subject&fields=id%2CthreadId%2CinternalDate%2ClabelIds%2Csnippet%2Cpayload%28headers%29"
        );
        assert_eq!(
            requests[2].0,
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/m2?format=metadata&metadataHeaders=From&metadataHeaders=Subject&fields=id%2CthreadId%2CinternalDate%2ClabelIds%2Csnippet%2Cpayload%28headers%29"
        );
    }

    #[test]
    fn rejects_an_account_mismatch_before_transport_work() {
        let transport = FakeTransport::new(vec![]);
        let mailbox = GmailMailbox::with_transport(account(ACCOUNT), transport.clone());
        let result = ready(mailbox.list_recent_envelopes(
            &account("account-2"),
            PageSize::new(1).unwrap_or_else(|error| panic!("{error}")),
            None,
        ));
        assert_eq!(result, Err(RemoteMailboxError::AuthorizationRequired));
        assert!(transport.requests().is_empty());
    }

    #[test]
    fn rejects_a_page_larger_than_requested_before_hydration() {
        let transport = FakeTransport::new(vec![json(
            200,
            r#"{"messages":[{"id":"m1","threadId":"t1"},{"id":"m2","threadId":"t2"}]}"#,
        )]);
        let mailbox = GmailMailbox::with_transport(account(ACCOUNT), transport.clone());
        let result = ready(mailbox.list_recent_envelopes(
            &account(ACCOUNT),
            PageSize::new(1).unwrap_or_else(|error| panic!("{error}")),
            None,
        ));
        assert_eq!(result, Err(RemoteMailboxError::InvalidResponse));
        assert_eq!(transport.requests().len(), 1);
    }

    #[test]
    fn rejects_dot_segment_message_ids_before_transport_work() {
        for value in [".", ".."] {
            let transport = FakeTransport::new(vec![]);
            let mailbox = GmailMailbox::with_transport(account(ACCOUNT), transport.clone());
            let selected_message = message_id(value);
            let result = ready(mailbox.fetch_message(&account(ACCOUNT), &selected_message));
            assert_eq!(result, Err(RemoteMailboxError::InvalidResponse));
            assert!(transport.requests().is_empty());
        }
    }

    #[test]
    fn skips_only_a_not_found_hydration() {
        let transport = FakeTransport::new(vec![
            json(
                200,
                r#"{"messages":[{"id":"gone","threadId":"tg"},{"id":"kept","threadId":"tk"}]}"#,
            ),
            json(404, r#"{"error":{"errors":[]}}"#),
            json(200, &metadata("kept", "tk", false)),
        ]);
        let mailbox = GmailMailbox::with_transport(account(ACCOUNT), transport);
        let page = ready(mailbox.list_recent_envelopes(
            &account(ACCOUNT),
            PageSize::new(2).unwrap_or_else(|error| panic!("{error}")),
            None,
        ))
        .unwrap_or_else(|error| panic!("list failed: {error}"));
        assert_eq!(page.items().len(), 1);
        assert_eq!(page.items()[0].message_id().as_str(), "kept");
    }

    #[test]
    fn fails_the_page_on_a_non_not_found_hydration_error() {
        let transport = FakeTransport::new(vec![
            json(
                200,
                r#"{"messages":[{"id":"first","threadId":"t1"},{"id":"second","threadId":"t2"}]}"#,
            ),
            json(500, r#"{"error":{"errors":[]}}"#),
            json(200, &metadata("second", "t2", false)),
        ]);
        let mailbox = GmailMailbox::with_transport(account(ACCOUNT), transport.clone());
        let result = ready(mailbox.list_recent_envelopes(
            &account(ACCOUNT),
            PageSize::new(2).unwrap_or_else(|error| panic!("{error}")),
            None,
        ));
        assert_eq!(result, Err(RemoteMailboxError::Transport));
        assert_eq!(transport.requests().len(), 2);
    }

    #[test]
    fn rejects_malformed_page_data_and_thread_mismatch() {
        for replies in [
            vec![json(
                200,
                r#"{"messages":[{"id":"bad id","threadId":"t"}]}"#,
            )],
            vec![
                json(200, r#"{"messages":[{"id":"m","threadId":"listed"}]}"#),
                json(200, &metadata("m", "hydrated", false)),
            ],
            vec![json(200, r#"{"nextPageToken":""}"#)],
        ] {
            let mailbox =
                GmailMailbox::with_transport(account(ACCOUNT), FakeTransport::new(replies));
            let result = ready(mailbox.list_recent_envelopes(
                &account(ACCOUNT),
                PageSize::new(1).unwrap_or_else(|error| panic!("{error}")),
                None,
            ));
            assert_eq!(result, Err(RemoteMailboxError::InvalidResponse));
        }
    }

    #[test]
    fn rejects_malformed_or_oversized_metadata() {
        let oversized = format!(
            r#"{{"id":"m","threadId":"t","internalDate":"0","snippet":"{}"}}"#,
            "x".repeat(1_025)
        );
        for metadata_body in [
            r#"{"id":"other","threadId":"t","internalDate":"0"}"#.to_owned(),
            r#"{"id":"m","threadId":"t","internalDate":"-1"}"#.to_owned(),
            r#"{"id":"m","threadId":"t","internalDate":"not-a-number"}"#.to_owned(),
            r#"{"threadId":"t","internalDate":"0"}"#.to_owned(),
            r#"{"id":"m","threadId":"t","internalDate":"0","labelIds":[1]}"#.to_owned(),
            r#"{"id":"m","threadId":"t","internalDate":"0","payload":{"headers":[{"name":"From","value":"line\nbreak"}]}}"#.to_owned(),
            oversized,
        ] {
            let mailbox = GmailMailbox::with_transport(
                account(ACCOUNT),
                FakeTransport::new(vec![
                    json(200, r#"{"messages":[{"id":"m","threadId":"t"}]}"#),
                    json(200, &metadata_body),
                ]),
            );
            let result = ready(mailbox.list_recent_envelopes(
                &account(ACCOUNT),
                PageSize::new(1).unwrap_or_else(|error| panic!("{error}")),
                None,
            ));
            assert_eq!(result, Err(RemoteMailboxError::InvalidResponse));
        }
    }

    #[test]
    fn accepts_missing_headers_and_rejects_duplicate_singletons() {
        let missing = r#"{"id":"m","threadId":"t","internalDate":"0","payload":{"headers":[]}}"#;
        let duplicate = r#"{"id":"m","threadId":"t","internalDate":"0","payload":{"headers":[{"name":"From","value":"one"},{"name":"from","value":"two"}]}}"#;

        let mailbox = GmailMailbox::with_transport(
            account(ACCOUNT),
            FakeTransport::new(vec![
                json(200, r#"{"messages":[{"id":"m","threadId":"t"}]}"#),
                json(200, missing),
            ]),
        );
        let page = ready(mailbox.list_recent_envelopes(
            &account(ACCOUNT),
            PageSize::new(1).unwrap_or_else(|error| panic!("{error}")),
            None,
        ))
        .unwrap_or_else(|error| panic!("list failed: {error}"));
        assert_eq!(page.items()[0].from().as_str(), "");
        assert_eq!(page.items()[0].subject().as_str(), "");

        let mailbox = GmailMailbox::with_transport(
            account(ACCOUNT),
            FakeTransport::new(vec![
                json(200, r#"{"messages":[{"id":"m","threadId":"t"}]}"#),
                json(200, duplicate),
            ]),
        );
        let result = ready(mailbox.list_recent_envelopes(
            &account(ACCOUNT),
            PageSize::new(1).unwrap_or_else(|error| panic!("{error}")),
            None,
        ));
        assert_eq!(result, Err(RemoteMailboxError::InvalidResponse));
    }

    #[test]
    fn fetches_padded_and_unpadded_raw_with_encoded_path() {
        for encoded in ["SGVsbG8", "SGVsbG8="] {
            let transport = FakeTransport::new(vec![
                json(200, &metadata("id/with?chars", "thread", false)),
                json(
                    200,
                    &format!(r#"{{"id":"id/with?chars","threadId":"thread","raw":"{encoded}"}}"#),
                ),
            ]);
            let mailbox = GmailMailbox::with_transport(account(ACCOUNT), transport.clone());
            let message_id = message_id("id/with?chars");
            let message = ready(mailbox.fetch_message(&account(ACCOUNT), &message_id))
                .unwrap_or_else(|error| panic!("fetch failed: {error}"));
            assert_eq!(message.content().as_bytes(), b"Hello");
            let requests = transport.requests();
            assert_eq!(requests.len(), 2);
            assert!(requests[0].0.contains("/messages/id%2Fwith%3Fchars?"));
            assert_eq!(requests[1].1, RAW_JSON_LIMIT);
            assert_eq!(
                requests[1].0,
                "https://gmail.googleapis.com/gmail/v1/users/me/messages/id%2Fwith%3Fchars?format=raw&fields=id%2CthreadId%2Craw"
            );
        }
    }

    #[test]
    fn rejects_raw_identity_mismatch_and_invalid_base64() {
        for raw in [
            r#"{"id":"other","threadId":"thread","raw":"SGVsbG8"}"#,
            r#"{"id":"m","threadId":"other","raw":"SGVsbG8"}"#,
            r#"{"id":"m","threadId":"thread","raw":"%%%"}"#,
        ] {
            let mailbox = GmailMailbox::with_transport(
                account(ACCOUNT),
                FakeTransport::new(vec![
                    json(200, &metadata("m", "thread", false)),
                    json(200, raw),
                ]),
            );
            let result = ready(mailbox.fetch_message(&account(ACCOUNT), &message_id("m")));
            assert_eq!(result, Err(RemoteMailboxError::InvalidResponse));
        }
    }

    #[test]
    fn enforces_encoded_and_decoded_raw_boundaries_without_large_allocations() {
        assert_eq!(decode_raw_with_limit("QQ", 1), Ok(vec![b'A']));
        assert_eq!(
            decode_raw_with_limit("QUE", 1),
            Err(RemoteMailboxError::InvalidResponse)
        );
        assert_eq!(
            decode_raw_with_limit("QUJDRA", 3),
            Err(RemoteMailboxError::InvalidResponse)
        );
    }

    #[test]
    fn rejects_content_length_and_stream_overflow_before_unbounded_growth() {
        assert_eq!(body_limit(200, RAW_JSON_LIMIT), RAW_JSON_LIMIT);
        assert_eq!(body_limit(403, RAW_JSON_LIMIT), JSON_LIMIT);
        assert!(reads_response_body(200));
        assert!(reads_response_body(403));
        assert!(!reads_response_body(500));
        assert!(matches!(
            BoundedBody::new(Some(5), 4),
            Err(TransportError::InvalidResponse)
        ));
        let mut body = BoundedBody::new(None, 4)
            .unwrap_or_else(|_| panic!("bounded body construction failed"));
        assert!(body.push(b"1234").is_ok());
        assert!(matches!(
            body.push(b"5"),
            Err(TransportError::InvalidResponse)
        ));
    }

    #[test]
    fn maps_documented_statuses_and_all_forbidden_reasons() {
        assert_eq!(
            map_status(401, b""),
            RemoteMailboxError::AuthorizationRequired
        );
        assert_eq!(map_status(404, b""), RemoteMailboxError::NotFound);
        assert_eq!(map_status(429, b""), RemoteMailboxError::RateLimited);
        assert_eq!(map_status(503, b""), RemoteMailboxError::Transport);
        for reason in [
            "dailyLimitExceeded",
            "rateLimitExceeded",
            "userRateLimitExceeded",
            "quotaExceeded",
        ] {
            let body = format!(r#"{{"error":{{"errors":[{{"reason":"{reason}"}}]}}}}"#);
            assert_eq!(
                map_status(403, body.as_bytes()),
                RemoteMailboxError::RateLimited
            );
        }
        for reason in ["authError", "insufficientPermissions", "domainPolicy"] {
            let body = format!(r#"{{"error":{{"errors":[{{"reason":"{reason}"}}]}}}}"#);
            assert_eq!(
                map_status(403, body.as_bytes()),
                RemoteMailboxError::AuthorizationRequired
            );
        }
        let later_reason =
            br#"{"error":{"errors":[{"reason":"unknown"},{"reason":"rateLimitExceeded"}]}}"#;
        assert_eq!(
            map_status(403, later_reason),
            RemoteMailboxError::RateLimited
        );
        assert_eq!(map_status(400, b""), RemoteMailboxError::InvalidResponse);
        assert_eq!(
            map_status(403, b"malformed"),
            RemoteMailboxError::InvalidResponse
        );
    }

    #[test]
    fn maps_network_and_oversized_transport_failures_without_payloads() {
        let network = GmailMailbox::with_transport(
            account(ACCOUNT),
            FakeTransport::new(vec![Reply::Network]),
        );
        let result = ready(network.list_recent_envelopes(
            &account(ACCOUNT),
            PageSize::new(1).unwrap_or_else(|error| panic!("{error}")),
            None,
        ));
        assert_eq!(result, Err(RemoteMailboxError::Transport));

        let oversized = GmailMailbox::with_transport(
            account(ACCOUNT),
            FakeTransport::new(vec![Reply::Response {
                status: 200,
                content_length: Some(JSON_LIMIT + 1),
                chunks: vec![],
            }]),
        );
        let result = ready(oversized.list_recent_envelopes(
            &account(ACCOUNT),
            PageSize::new(1).unwrap_or_else(|error| panic!("{error}")),
            None,
        ));
        assert_eq!(result, Err(RemoteMailboxError::InvalidResponse));

        let server_error = GmailMailbox::with_transport(
            account(ACCOUNT),
            FakeTransport::new(vec![Reply::Response {
                status: 503,
                content_length: Some(usize::MAX),
                chunks: vec![vec![0; 8]],
            }]),
        );
        let result = ready(server_error.list_recent_envelopes(
            &account(ACCOUNT),
            PageSize::new(1).unwrap_or_else(|error| panic!("{error}")),
            None,
        ));
        assert_eq!(result, Err(RemoteMailboxError::Transport));
    }

    #[test]
    fn debug_output_is_redacted() {
        let mailbox = GmailMailbox::with_transport(account(ACCOUNT), FakeTransport::new(vec![]));
        assert_eq!(format!("{mailbox:?}"), "GmailMailbox([REDACTED])");
        assert!(!format!("{mailbox:?}").contains(ACCOUNT));
    }

    #[test]
    fn dropping_a_pending_operation_releases_future_owned_state() {
        let dropped = Arc::new(AtomicBool::new(false));
        let mailbox = GmailMailbox::with_transport(
            account(ACCOUNT),
            FakeTransport::new(vec![Reply::Pending(Arc::clone(&dropped))]),
        );
        let selected_account = account(ACCOUNT);
        let mut future = mailbox.list_recent_envelopes(
            &selected_account,
            PageSize::new(1).unwrap_or_else(|error| panic!("{error}")),
            None,
        );
        assert!(poll_once(future.as_mut()).is_pending());
        assert!(!dropped.load(Ordering::SeqCst));
        drop(future);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn exchange_posts_exact_ordered_parameters_and_parses_a_rotated_token() {
        let (grant, request) = captured_exchange(Some("non-confidential-secret"));
        let post = FakePostTransport::new(vec![json(
            200,
            &token_success_body(Some("rotated-refresh-token")),
        )]);
        let transport = GmailTokenTransport::with_transport(post.clone());
        let response = ready(transport.exchange(request))
            .unwrap_or_else(|error| panic!("exchange failed: {error}"));

        assert_eq!(response.access_token().as_str(), "fresh-access-token");
        assert_eq!(response.expires_in(), Duration::from_secs(3_599));
        assert_eq!(
            response.rotated_refresh_token().map(|token| token.as_str()),
            Some("rotated-refresh-token")
        );

        let requests = post.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0, TOKEN_ENDPOINT);
        assert_eq!(
            requests[0].1.as_str(),
            format!(
                "grant_type=authorization_code&code=exchange-code&code_verifier={}&client_id=public-test-client&redirect_uri=app.tersa.oauth.test%3A%2Foauth%2Fcallback&client_secret=non-confidential-secret",
                grant.verifier()
            )
        );
    }

    #[test]
    fn exchange_without_a_client_secret_parses_an_absent_rotated_token() {
        let (grant, request) = captured_exchange(None);
        let post = FakePostTransport::new(vec![json(200, &token_success_body(None))]);
        let transport = GmailTokenTransport::with_transport(post.clone());
        let response = ready(transport.exchange(request))
            .unwrap_or_else(|error| panic!("exchange failed: {error}"));

        assert_eq!(response.access_token().as_str(), "fresh-access-token");
        assert_eq!(response.expires_in(), Duration::from_secs(3_599));
        assert!(response.rotated_refresh_token().is_none());

        let requests = post.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0, TOKEN_ENDPOINT);
        assert_eq!(
            requests[0].1.as_str(),
            format!(
                "grant_type=authorization_code&code=exchange-code&code_verifier={}&client_id=public-test-client&redirect_uri=app.tersa.oauth.test%3A%2Foauth%2Fcallback",
                grant.verifier()
            )
        );
    }

    #[test]
    fn refresh_posts_exact_ordered_parameters_with_and_without_a_client_secret() {
        let request = captured_refresh(Some("non-confidential-secret"));
        let post = FakePostTransport::new(vec![json(200, &token_success_body(None))]);
        let transport = GmailTokenTransport::with_transport(post.clone());
        let response = ready(transport.refresh(request))
            .unwrap_or_else(|error| panic!("refresh failed: {error}"));
        assert_eq!(response.access_token().as_str(), "fresh-access-token");
        assert!(response.rotated_refresh_token().is_none());
        let requests = post.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0, TOKEN_ENDPOINT);
        assert_eq!(
            requests[0].1.as_str(),
            "grant_type=refresh_token&refresh_token=stored-refresh-token&client_id=public-test-client&client_secret=non-confidential-secret"
        );

        let request = captured_refresh(None);
        let post = FakePostTransport::new(vec![json(
            200,
            &token_success_body(Some("rotated-refresh-token")),
        )]);
        let transport = GmailTokenTransport::with_transport(post.clone());
        let response = ready(transport.refresh(request))
            .unwrap_or_else(|error| panic!("refresh failed: {error}"));
        assert_eq!(response.access_token().as_str(), "fresh-access-token");
        assert_eq!(
            response.rotated_refresh_token().map(|token| token.as_str()),
            Some("rotated-refresh-token")
        );
        let requests = post.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].1.as_str(),
            "grant_type=refresh_token&refresh_token=stored-refresh-token&client_id=public-test-client"
        );
    }

    #[test]
    fn maps_invalid_grant_to_invalid_grant() {
        let (_, request) = captured_exchange(None);
        let transport = GmailTokenTransport::with_transport(FakePostTransport::new(vec![json(
            400,
            r#"{"error":"invalid_grant","error_description":"the grant expired"}"#,
        )]));
        assert_eq!(
            ready(transport.exchange(request)).err(),
            Some(TokenTransportError::InvalidGrant)
        );
    }

    #[test]
    fn maps_other_provider_errors_to_provider_rejected() {
        // `invalid_token` is included deliberately: the token endpoint mapping
        // must NOT special-case it — that answer is only meaningful (and only
        // mapped) on the revoke endpoint.
        for body in [
            r#"{"error":"invalid_client","error_description":"unknown client"}"#,
            r#"{"error":"access_denied"}"#,
            r#"{"error":"invalid_token"}"#,
        ] {
            let (_, request) = captured_exchange(None);
            let transport =
                GmailTokenTransport::with_transport(FakePostTransport::new(vec![json(400, body)]));
            assert_eq!(
                ready(transport.exchange(request)).err(),
                Some(TokenTransportError::ProviderRejected)
            );
        }
    }

    #[test]
    fn maps_unparsable_success_and_error_bodies_to_malformed_response() {
        for (status, body) in [
            (200, "not json"),
            (200, r#"{"access_token":"fresh-access-token"}"#),
            (
                200,
                r#"{"access_token":"fresh-access-token","expires_in":"3599","token_type":"Bearer"}"#,
            ),
            (400, "not json"),
            (400, r#"{"error_description":"missing the error code"}"#),
        ] {
            let (_, request) = captured_exchange(None);
            let transport =
                GmailTokenTransport::with_transport(FakePostTransport::new(vec![json(
                    status, body,
                )]));
            assert_eq!(
                ready(transport.exchange(request)).err(),
                Some(TokenTransportError::MalformedResponse)
            );
        }
    }

    fn jwt(payload: &str) -> String {
        use base64::Engine as _;
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "{}.{}.{}",
            engine.encode(br#"{"alg":"RS256"}"#),
            engine.encode(payload.as_bytes()),
            engine.encode(b"signature")
        )
    }

    #[test]
    fn parse_token_response_decodes_a_present_id_token() {
        let payload = r#"{"sub":"sub-123","aud":"public-client","iss":"https://accounts.google.com","iat":1000,"exp":5000}"#;
        let body = format!(
            r#"{{"access_token":"a","expires_in":3599,"token_type":"Bearer","id_token":"{}"}}"#,
            jwt(payload)
        );
        let (_access, _expires, _refresh, claims, gmail_read_granted) =
            parse_token_response(body.as_bytes())
                .unwrap_or_else(|error| panic!("expected a token response: {error:?}"))
                .into_parts();
        assert!(claims.is_some());
        assert!(gmail_read_granted);
    }

    #[test]
    fn parse_token_response_without_an_id_token_carries_no_claims() {
        let body = r#"{"access_token":"a","expires_in":3599,"token_type":"Bearer"}"#;
        let (_access, _expires, _refresh, claims, gmail_read_granted) =
            parse_token_response(body.as_bytes())
                .unwrap_or_else(|error| panic!("expected a token response: {error:?}"))
                .into_parts();
        assert!(claims.is_none());
        assert!(gmail_read_granted);
    }

    #[test]
    fn token_response_records_an_explicit_scope_without_gmail_read_access() {
        let under_scoped =
            br#"{"access_token":"a","expires_in":3599,"token_type":"Bearer","scope":"openid"}"#;
        let response = parse_token_response(under_scoped)
            .unwrap_or_else(|error| panic!("expected a parsed token response: {error:?}"));
        assert!(!response.gmail_read_granted());

        let fully_scoped = br#"{"access_token":"a","expires_in":3599,"token_type":"Bearer","scope":"openid https://www.googleapis.com/auth/gmail.readonly"}"#;
        let response = parse_token_response(fully_scoped)
            .unwrap_or_else(|error| panic!("expected a parsed token response: {error:?}"));
        assert!(response.gmail_read_granted());
    }

    #[test]
    fn under_scoped_response_preserves_tokens_despite_a_malformed_id_token() {
        let under_scoped = br#"{"access_token":"access","expires_in":3599,"refresh_token":"refresh","token_type":"Bearer","scope":"openid","id_token":"malformed"}"#;
        let (access, _expires, refresh, claims, gmail_read_granted) =
            parse_token_response(under_scoped)
                .unwrap_or_else(|error| panic!("expected an under-scoped response: {error:?}"))
                .into_parts();
        assert_eq!(access.as_str(), "access");
        assert_eq!(refresh.as_deref().map(String::as_str), Some("refresh"));
        assert!(claims.is_none());
        assert!(!gmail_read_granted);
    }

    #[test]
    fn parse_id_token_claims_rejects_structurally_malformed_tokens() {
        let good = r#"{"sub":"s","aud":"c","iss":"i","iat":1,"exp":2}"#;
        let engine = {
            use base64::Engine as _;
            |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
        };
        let good_payload = engine(good.as_bytes());
        let cases: Vec<String> = vec![
            "onlyonesegment".to_owned(),
            "two.segments".to_owned(),
            "four.seg.ments.here".to_owned(),
            "header.!!!notbase64.signature".to_owned(),
            jwt("not json"),
            // Each missing a single required claim (sub / aud / iss / iat / exp).
            jwt(r#"{"aud":"c","iss":"i","iat":1,"exp":2}"#),
            jwt(r#"{"sub":"s","iss":"i","iat":1,"exp":2}"#),
            jwt(r#"{"sub":"s","aud":"c","iat":1,"exp":2}"#),
            jwt(r#"{"sub":"s","aud":"c","iss":"i","exp":2}"#),
            jwt(r#"{"sub":"s","aud":"c","iss":"i","iat":1}"#),
            // Structurally incomplete JWS: empty or malformed header/signature.
            format!(".{good_payload}.{}", engine(b"sig")),
            format!("{}.{good_payload}.", engine(b"header")),
            format!("!!!.{good_payload}.{}", engine(b"sig")),
            format!("{}.{good_payload}.!!!", engine(b"header")),
        ];
        for token in cases {
            assert_eq!(
                parse_id_token_claims(&token).err(),
                Some(TokenTransportError::MalformedResponse),
                "token {token} should be rejected"
            );
        }
    }

    #[test]
    fn parse_id_token_claims_accepts_an_array_audience() {
        let token =
            jwt(r#"{"sub":"s","aud":["a","b"],"iss":"accounts.google.com","iat":1,"exp":2}"#);
        assert!(parse_id_token_claims(&token).is_ok());
    }

    #[test]
    fn maps_network_and_oversized_token_failures_without_payloads() {
        let (_, request) = captured_exchange(None);
        let transport =
            GmailTokenTransport::with_transport(FakePostTransport::new(vec![Reply::Network]));
        assert_eq!(
            ready(transport.exchange(request)).err(),
            Some(TokenTransportError::Transport)
        );

        let (_, request) = captured_exchange(None);
        let transport =
            GmailTokenTransport::with_transport(FakePostTransport::new(vec![Reply::Response {
                status: 200,
                content_length: Some(TOKEN_RESPONSE_LIMIT + 1),
                chunks: vec![],
            }]));
        assert_eq!(
            ready(transport.exchange(request)).err(),
            Some(TokenTransportError::MalformedResponse)
        );

        let (_, request) = captured_exchange(None);
        let transport =
            GmailTokenTransport::with_transport(FakePostTransport::new(vec![Reply::Response {
                status: 200,
                content_length: None,
                chunks: vec![vec![b'x'; TOKEN_RESPONSE_LIMIT], vec![b'x']],
            }]));
        assert_eq!(
            ready(transport.exchange(request)).err(),
            Some(TokenTransportError::MalformedResponse)
        );
    }

    #[test]
    fn revoke_posts_the_token_and_maps_success_and_failures() {
        let token = Zeroizing::new("stored-refresh-token".to_owned());

        let post = FakePostTransport::new(vec![Reply::Response {
            status: 200,
            content_length: Some(0),
            chunks: vec![],
        }]);
        let transport = GmailTokenTransport::with_transport(post.clone());
        assert_eq!(ready(transport.revoke(&token)), Ok(()));
        let requests = post.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0, REVOKE_ENDPOINT);
        assert_eq!(requests[0].1.as_str(), "token=stored-refresh-token");

        // Google's answer for an unknown or already-revoked token is HTTP 400
        // `invalid_token`: kept distinct so the caller can confirm the desired
        // end state instead of reporting an unconfirmed revoke.
        let transport = GmailTokenTransport::with_transport(FakePostTransport::new(vec![json(
            400,
            r#"{"error":"invalid_token"}"#,
        )]));
        assert_eq!(
            ready(transport.revoke(&token)),
            Err(TokenTransportError::InvalidToken)
        );

        // A well-formed `invalid_grant` revoke answer keeps its own variant.
        let transport = GmailTokenTransport::with_transport(FakePostTransport::new(vec![json(
            400,
            r#"{"error":"invalid_grant"}"#,
        )]));
        assert_eq!(
            ready(transport.revoke(&token)),
            Err(TokenTransportError::InvalidGrant)
        );

        let transport = GmailTokenTransport::with_transport(FakePostTransport::new(vec![json(
            400,
            r#"{"error":"unsupported_token_type"}"#,
        )]));
        assert_eq!(
            ready(transport.revoke(&token)),
            Err(TokenTransportError::ProviderRejected)
        );

        let transport = GmailTokenTransport::with_transport(FakePostTransport::new(vec![json(
            400, "not json",
        )]));
        assert_eq!(
            ready(transport.revoke(&token)),
            Err(TokenTransportError::MalformedResponse)
        );

        let transport =
            GmailTokenTransport::with_transport(FakePostTransport::new(vec![Reply::Network]));
        assert_eq!(
            ready(transport.revoke(&token)),
            Err(TokenTransportError::Transport)
        );
    }

    #[test]
    fn dropping_a_pending_token_operation_releases_future_owned_state() {
        let dropped = Arc::new(AtomicBool::new(false));
        let transport =
            GmailTokenTransport::with_transport(FakePostTransport::new(vec![Reply::Pending(
                Arc::clone(&dropped),
            )]));
        let (_, request) = captured_exchange(None);
        let mut future = transport.exchange(request);
        assert!(poll_once(future.as_mut()).is_pending());
        assert!(!dropped.load(Ordering::SeqCst));
        drop(future);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn token_transport_debug_output_is_redacted() {
        let transport = GmailTokenTransport::with_transport(FakePostTransport::new(vec![]));
        let rendered = format!("{transport:?}");
        assert_eq!(rendered, "GmailTokenTransport([REDACTED])");
        for secret in [
            "fresh-access-token",
            "stored-refresh-token",
            "non-confidential-secret",
        ] {
            assert!(!rendered.contains(secret));
        }
    }

    #[test]
    fn validates_access_tokens_without_constructing_a_network_client() {
        use super::{MAX_ACCESS_TOKEN_LEN, validate_access_token};

        assert!(validate_access_token("short-lived-token").is_ok());
        assert_eq!(
            validate_access_token(""),
            Err(RemoteMailboxError::AuthorizationRequired)
        );
        assert_eq!(
            validate_access_token("line\nbreak"),
            Err(RemoteMailboxError::AuthorizationRequired)
        );
        assert_eq!(
            validate_access_token(&"x".repeat(MAX_ACCESS_TOKEN_LEN + 1)),
            Err(RemoteMailboxError::AuthorizationRequired)
        );
    }
}
