// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Defines portable mailbox values with bounded, redacted user-controlled data.
//!
//! These values contain no provider DTOs, storage details, or I/O behavior.

use std::fmt;

const MAX_IDENTIFIER_LEN: usize = 256;
const MAX_HEADER_LEN: usize = 1_024;

/// Reports a rejected bounded textual value without exposing its content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MailboxInvariantError {
    /// The supplied value was empty where a value is required.
    Empty,
    /// The supplied value exceeds its documented byte limit.
    TooLong {
        /// The rejected byte length.
        len: usize,
        /// The maximum accepted byte length.
        max_len: usize,
    },
    /// The supplied value contains a disallowed character.
    InvalidCharacter,
    /// An account identifier looked like an email address.
    EmailShapedAccountId,
    /// The supplied timestamp predates the Unix epoch.
    NegativeTimestamp,
}

impl fmt::Display for MailboxInvariantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Empty => "the mailbox value must not be empty",
            Self::TooLong { .. } => "the mailbox value exceeds its maximum length",
            Self::InvalidCharacter => "the mailbox value contains an invalid character",
            Self::EmailShapedAccountId => "the account identifier must not be an email address",
            Self::NegativeTimestamp => "the mailbox timestamp must not be negative",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for MailboxInvariantError {}

/// Reports rejected opaque message content without exposing any bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MessageContentError {
    /// The supplied decoded content exceeds the defensive maximum.
    TooLarge {
        /// The rejected decoded byte length.
        len: usize,
    },
}

impl fmt::Display for MessageContentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the message content exceeds its maximum decoded length")
    }
}

impl std::error::Error for MessageContentError {}

macro_rules! opaque_identifier {
    ($name:ident, $docs:literal, $validate:ident) => {
        #[doc = $docs]
        #[derive(Clone, Eq, Hash, PartialEq)]
        pub struct $name(String);

        impl $name {
            /// Creates a validated opaque identifier.
            ///
            /// # Errors
            ///
            /// Returns [`MailboxInvariantError`] if the identifier is empty,
            /// too long, or does not contain only visible non-whitespace ASCII
            /// characters (`!` through `~`).
            pub fn new<T: Into<String>>(value: T) -> Result<Self, MailboxInvariantError> {
                let value = value.into();
                $validate(&value)?;
                Ok(Self(value))
            }

            /// Returns the opaque identifier text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}([REDACTED])", stringify!($name))
            }
        }
    };
}

opaque_identifier!(
    AccountId,
    "Identifies a locally assigned opaque account, never an email address.",
    validate_account_identifier
);
opaque_identifier!(
    MessageId,
    "Identifies one provider-neutral mailbox message.",
    validate_identifier
);
opaque_identifier!(
    ThreadId,
    "Identifies one provider-neutral mailbox thread.",
    validate_identifier
);

/// Represents milliseconds since the Unix epoch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UnixTimestampMillis(i64);

impl UnixTimestampMillis {
    /// Creates a non-negative Unix timestamp in milliseconds.
    ///
    /// # Errors
    ///
    /// Returns [`MailboxInvariantError::NegativeTimestamp`] for negative input.
    pub fn new(value: i64) -> Result<Self, MailboxInvariantError> {
        if value < 0 {
            return Err(MailboxInvariantError::NegativeTimestamp);
        }
        Ok(Self(value))
    }

    /// Returns milliseconds since the Unix epoch.
    #[must_use]
    pub fn as_millis(self) -> i64 {
        self.0
    }
}

/// Holds bounded Unicode header text without control characters.
#[derive(Clone, Eq, PartialEq)]
pub struct HeaderText(String);

impl HeaderText {
    /// Creates validated header text.
    ///
    /// # Errors
    ///
    /// Returns [`MailboxInvariantError`] when text exceeds 1,024 bytes or
    /// contains a Unicode control character. Empty text is accepted.
    pub fn new<T: Into<String>>(value: T) -> Result<Self, MailboxInvariantError> {
        let value = value.into();
        if value.len() > MAX_HEADER_LEN {
            return Err(MailboxInvariantError::TooLong {
                len: value.len(),
                max_len: MAX_HEADER_LEN,
            });
        }
        if value.chars().any(char::is_control) {
            return Err(MailboxInvariantError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    /// Returns the header text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for HeaderText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HeaderText([REDACTED])")
    }
}

/// Summarizes a message without exposing its opaque content.
#[derive(Clone, Eq, PartialEq)]
pub struct MessageEnvelope {
    message_id: MessageId,
    thread_id: ThreadId,
    from: HeaderText,
    subject: HeaderText,
    preview: HeaderText,
    received_at: UnixTimestampMillis,
    unread: bool,
}

impl MessageEnvelope {
    /// Creates a complete mailbox message summary.
    #[allow(
        clippy::too_many_arguments,
        reason = "the envelope has seven required fields"
    )]
    #[must_use]
    pub fn new(
        message_id: MessageId,
        thread_id: ThreadId,
        from: HeaderText,
        subject: HeaderText,
        preview: HeaderText,
        received_at: UnixTimestampMillis,
        unread: bool,
    ) -> Self {
        Self {
            message_id,
            thread_id,
            from,
            subject,
            preview,
            received_at,
            unread,
        }
    }

    /// Returns the message identifier.
    #[must_use]
    pub fn message_id(&self) -> &MessageId {
        &self.message_id
    }
    /// Returns the thread identifier.
    #[must_use]
    pub fn thread_id(&self) -> &ThreadId {
        &self.thread_id
    }
    /// Returns the sender header text.
    #[must_use]
    pub fn from(&self) -> &HeaderText {
        &self.from
    }
    /// Returns the subject header text.
    #[must_use]
    pub fn subject(&self) -> &HeaderText {
        &self.subject
    }
    /// Returns the preview header text.
    #[must_use]
    pub fn preview(&self) -> &HeaderText {
        &self.preview
    }
    /// Returns the received timestamp.
    #[must_use]
    pub fn received_at(&self) -> UnixTimestampMillis {
        self.received_at
    }
    /// Returns whether the message is unread.
    #[must_use]
    pub fn is_unread(&self) -> bool {
        self.unread
    }
}

impl fmt::Debug for MessageEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MessageEnvelope")
            .field("message_id", &self.message_id)
            .field("thread_id", &self.thread_id)
            .field("from", &"[REDACTED]")
            .field("subject", &"[REDACTED]")
            .field("preview", &"[REDACTED]")
            .field("received_at", &self.received_at)
            .field("unread", &self.unread)
            .finish()
    }
}

/// Holds opaque decoded message data with a provider-neutral defensive bound.
#[derive(Clone, Eq, PartialEq)]
pub struct MessageContent(Vec<u8>);

impl MessageContent {
    /// The maximum accepted decoded content length: 64 MiB.
    pub const MAX_LEN: usize = 64 * 1024 * 1024;

    /// Creates bounded opaque decoded message content.
    ///
    /// # Errors
    ///
    /// Returns [`MessageContentError::TooLarge`] when content exceeds
    /// [`Self::MAX_LEN`].
    pub fn new(value: Vec<u8>) -> Result<Self, MessageContentError> {
        if value.len() > Self::MAX_LEN {
            return Err(MessageContentError::TooLarge { len: value.len() });
        }
        Ok(Self(value))
    }
    /// Returns the opaque decoded bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Returns the decoded byte length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Returns whether content has zero decoded bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Returns the decoded bytes without copying them.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for MessageContent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MessageContent")
            .field("len", &self.0.len())
            .field("content", &"[REDACTED]")
            .finish()
    }
}

/// Combines a redacted envelope with opaque decoded content.
#[derive(Clone, Eq, PartialEq)]
pub struct Message {
    envelope: MessageEnvelope,
    content: MessageContent,
}

impl Message {
    /// Creates a message from its envelope and decoded content.
    #[must_use]
    pub fn new(envelope: MessageEnvelope, content: MessageContent) -> Self {
        Self { envelope, content }
    }
    /// Returns the message envelope.
    #[must_use]
    pub fn envelope(&self) -> &MessageEnvelope {
        &self.envelope
    }
    /// Returns the opaque decoded content.
    #[must_use]
    pub fn content(&self) -> &MessageContent {
        &self.content
    }
    /// Returns the decoded content, dropping the envelope.
    #[must_use]
    pub fn into_content(self) -> MessageContent {
        self.content
    }
}

impl fmt::Debug for Message {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Message")
            .field("envelope", &self.envelope)
            .field("content", &self.content)
            .finish()
    }
}

fn validate_identifier(value: &str) -> Result<(), MailboxInvariantError> {
    if value.is_empty() {
        return Err(MailboxInvariantError::Empty);
    }
    if value.len() > MAX_IDENTIFIER_LEN {
        return Err(MailboxInvariantError::TooLong {
            len: value.len(),
            max_len: MAX_IDENTIFIER_LEN,
        });
    }
    if !value.bytes().all(|byte| (b'!'..=b'~').contains(&byte)) {
        return Err(MailboxInvariantError::InvalidCharacter);
    }
    Ok(())
}

fn validate_account_identifier(value: &str) -> Result<(), MailboxInvariantError> {
    validate_identifier(value)?;
    if value.contains('@') {
        return Err(MailboxInvariantError::EmailShapedAccountId);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests assert valid fixtures")]
    use super::*;

    fn envelope() -> MessageEnvelope {
        MessageEnvelope::new(
            MessageId::new("message-1").unwrap(),
            ThreadId::new("thread-1").unwrap(),
            HeaderText::new("from-sentinel").unwrap(),
            HeaderText::new("subject-sentinel").unwrap(),
            HeaderText::new("preview-sentinel").unwrap(),
            UnixTimestampMillis::new(0).unwrap(),
            true,
        )
    }

    #[test]
    fn identifiers_enforce_visible_ascii_and_byte_bounds() {
        assert_identifier_invariants(AccountId::new, true);
        assert_identifier_invariants(MessageId::new, false);
        assert_identifier_invariants(ThreadId::new, false);
        assert_eq!(AccountId::new("account").unwrap().as_str(), "account");
    }

    fn assert_identifier_invariants<T>(
        make: impl Fn(String) -> Result<T, MailboxInvariantError>,
        rejects_email: bool,
    ) {
        assert!(make("a".repeat(256)).is_ok());
        assert!(matches!(
            make(String::new()),
            Err(MailboxInvariantError::Empty)
        ));
        assert!(matches!(
            make("a".repeat(257)),
            Err(MailboxInvariantError::TooLong {
                len: 257,
                max_len: 256
            })
        ));
        assert!(matches!(
            make("non-ascii-é".to_owned()),
            Err(MailboxInvariantError::InvalidCharacter)
        ));
        assert!(matches!(
            make("line\nbreak".to_owned()),
            Err(MailboxInvariantError::InvalidCharacter)
        ));
        assert!(matches!(
            make("space value".to_owned()),
            Err(MailboxInvariantError::InvalidCharacter)
        ));
        if rejects_email {
            assert!(matches!(
                make("person@example.test".to_owned()),
                Err(MailboxInvariantError::EmailShapedAccountId)
            ));
        }
    }

    #[test]
    fn identifier_debug_output_redacts_every_payload() {
        for debug in [
            format!("{:?}", AccountId::new("account-sentinel").unwrap()),
            format!("{:?}", MessageId::new("message-sentinel").unwrap()),
            format!("{:?}", ThreadId::new("thread-sentinel").unwrap()),
        ] {
            assert!(debug.contains("[REDACTED]"));
            assert!(!debug.contains("sentinel"));
        }
        assert_eq!(
            format!("{:?}", AccountId::new("account-sentinel").unwrap()),
            "AccountId([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", MessageId::new("message-sentinel").unwrap()),
            "MessageId([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", ThreadId::new("thread-sentinel").unwrap()),
            "ThreadId([REDACTED])"
        );
    }

    #[test]
    fn timestamp_and_headers_enforce_their_invariants() {
        assert_eq!(
            UnixTimestampMillis::new(-1),
            Err(MailboxInvariantError::NegativeTimestamp)
        );
        assert_eq!(UnixTimestampMillis::new(42).unwrap().as_millis(), 42);
        assert_eq!(HeaderText::new("").unwrap().as_str(), "");
        assert_eq!(
            format!("{:?}", HeaderText::new("header-sentinel").unwrap()),
            "HeaderText([REDACTED])"
        );
        assert!(HeaderText::new("é".repeat(512)).is_ok());
        assert!(matches!(
            HeaderText::new("é".repeat(513)),
            Err(MailboxInvariantError::TooLong {
                len: 1026,
                max_len: 1024
            })
        ));
        assert_eq!(
            HeaderText::new("a\u{0000}b"),
            Err(MailboxInvariantError::InvalidCharacter)
        );
    }

    #[test]
    fn message_content_enforces_bound_and_debug_redacts_user_values() {
        let content = MessageContent::new(b"body-sentinel".to_vec()).unwrap();
        assert_eq!(content.as_bytes(), b"body-sentinel");
        assert_eq!(content.len(), 13);
        assert!(!content.is_empty());
        assert!(MessageContent::new(vec![0; MessageContent::MAX_LEN]).is_ok());
        assert_eq!(
            MessageContent::new(vec![0; MessageContent::MAX_LEN + 1]),
            Err(MessageContentError::TooLarge {
                len: MessageContent::MAX_LEN + 1
            })
        );
        let message = Message::new(envelope(), content.clone());
        assert_eq!(message.content(), &content);
        let debug = format!("{message:?}");
        for sentinel in [
            "message-1",
            "thread-1",
            "from-sentinel",
            "subject-sentinel",
            "preview-sentinel",
            "body-sentinel",
        ] {
            assert!(!debug.contains(sentinel));
        }
        assert!(debug.contains("[REDACTED]"));
        assert_eq!(
            content,
            MessageContent::new(b"body-sentinel".to_vec()).unwrap()
        );
    }

    #[test]
    fn envelope_accessors_preserve_structural_fields() {
        let value = envelope();
        assert_eq!(value.message_id().as_str(), "message-1");
        assert_eq!(value.thread_id().as_str(), "thread-1");
        assert_eq!(value.from().as_str(), "from-sentinel");
        assert_eq!(value.subject().as_str(), "subject-sentinel");
        assert_eq!(value.preview().as_str(), "preview-sentinel");
        assert_eq!(value.received_at().as_millis(), 0);
        assert!(value.is_unread());
    }
}
