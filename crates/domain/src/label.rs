// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Defines account-bound labels, complete membership and bounded label catalogs.
//!
//! IDs use a defensive URL-segment-safe ASCII subset, not an asserted provider
//! grammar. Names retain exact UTF-8 bytes, including controls; presentation must
//! sanitize them. Trusted provider decoding or persisted classification supplies
//! label kind, never a name or guessed ID prefix. A [`UserLabel`](crate::label::UserLabel)
//! retains that classification and account, not proof of live provider kind or
//! continued existence; dispatch still needs fresh verification.
//! Collections reject duplicates and overflow rather than silently losing data.

use std::fmt;

use crate::mailbox::AccountId;

/// Reports invalid label values without retaining provider data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LabelError {
    /// The ID is empty, too long, or outside the defensive ASCII subset.
    InvalidId,
    /// The name is empty or exceeds the byte bound.
    InvalidName,
    /// A collection exceeds its documented bound.
    TooManyLabels,
    /// A collection contains the same ID more than once.
    DuplicateId,
    /// A definition belongs to another account.
    WrongAccount,
    /// A system definition cannot serve as a User label.
    NotUser,
}
impl fmt::Display for LabelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidId => "invalid label identifier",
            Self::InvalidName => "invalid label name length",
            Self::TooManyLabels => "label collection exceeds its bound",
            Self::DuplicateId => "duplicate label identifier",
            Self::WrongAccount => "label belongs to another account",
            Self::NotUser => "system label cannot be used as a User label",
        })
    }
}
impl std::error::Error for LabelError {}

/// Identifies a label using a bounded, URL-segment-safe opaque value.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LabelId(String);
impl LabelId {
    /// Defensive byte limit consistent with existing mailbox identifier bounds.
    pub const MAX_LEN: usize = 256;

    /// Validates an opaque ID without escaping or normalizing it.
    ///
    /// # Errors
    ///
    /// Rejects empty input, more than 256 bytes, or anything except ASCII
    /// letters, digits, `_` and `-`. Dots, percent escapes, path separators and
    /// query delimiters are excluded defensively, not as a provider guarantee.
    pub fn new<T: Into<String>>(value: T) -> Result<Self, LabelError> {
        let value = value.into();
        if !valid_segment(&value, Self::MAX_LEN) {
            return Err(LabelError::InvalidId);
        }
        Ok(Self(value))
    }

    /// Returns the exact identifier for trusted persistence or transport.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for LabelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LabelId([REDACTED])")
    }
}

pub(crate) fn valid_segment(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Holds an exact provider label name, without display sanitization or normalization.
#[derive(Clone, Eq, PartialEq)]
pub struct LabelName(String);
impl LabelName {
    /// Maximum accepted UTF-8 byte length, per the T4 product contract.
    pub const MAX_LEN: usize = 1_024;

    /// Retains a nonempty name exactly as provided.
    ///
    /// # Errors
    ///
    /// Rejects zero bytes or more than 1,024 UTF-8 bytes. Whitespace, controls
    /// and canonically equivalent Unicode spellings remain distinct raw values.
    pub fn new<T: Into<String>>(value: T) -> Result<Self, LabelError> {
        let value = value.into();
        if value.is_empty() || value.len() > Self::MAX_LEN {
            return Err(LabelError::InvalidName);
        }
        Ok(Self(value))
    }

    /// Returns exact provider text; use sanitized presentation values when rendering.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for LabelName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LabelName([REDACTED])")
    }
}

/// Distinguishes provider-owned definitions from user-managed definitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LabelKind {
    /// Provider-owned definition, never a User-label operation target.
    System,
    /// User-managed definition, subject to fresh verification before dispatch.
    User,
}

/// Associates an immutable label ID and exact name with one account and kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LabelDefinition {
    account: AccountId,
    id: LabelId,
    name: LabelName,
    kind: LabelKind,
}
impl LabelDefinition {
    /// Binds validated provider label metadata to its owning account.
    ///
    /// # Errors
    ///
    /// Rejects known reserved system IDs marked User. Trusted decoding must
    /// supply the provider's actual kind; unknown system IDs are not inferred.
    pub fn new(
        account: AccountId,
        id: LabelId,
        name: LabelName,
        kind: LabelKind,
    ) -> Result<Self, LabelError> {
        if kind == LabelKind::User && is_reserved_system_id(id.as_str()) {
            return Err(LabelError::NotUser);
        }
        Ok(Self {
            account,
            id,
            name,
            kind,
        })
    }

    /// Returns the owning account.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }
    /// Returns the immutable label ID.
    #[must_use]
    pub fn id(&self) -> &LabelId {
        &self.id
    }
    /// Returns the exact, unsanitized name.
    #[must_use]
    pub fn name(&self) -> &LabelName {
        &self.name
    }
    /// Returns the validated provider kind.
    #[must_use]
    pub fn kind(&self) -> LabelKind {
        self.kind
    }

    /// Produces an account-bound User target, excluding system definitions.
    ///
    /// # Errors
    ///
    /// Returns [`LabelError::NotUser`] for a System definition.
    pub fn user_label(&self) -> Result<UserLabel, LabelError> {
        if self.kind != LabelKind::User {
            return Err(LabelError::NotUser);
        }
        UserLabel::from_classified_id(self.account.clone(), self.id.clone())
    }
}

fn is_reserved_system_id(id: &str) -> bool {
    matches!(
        id,
        "INBOX"
            | "SPAM"
            | "TRASH"
            | "UNREAD"
            | "STARRED"
            | "IMPORTANT"
            | "SENT"
            | "DRAFT"
            | "CHAT"
            | "CATEGORY_PERSONAL"
            | "CATEGORY_SOCIAL"
            | "CATEGORY_PROMOTIONS"
            | "CATEGORY_UPDATES"
            | "CATEGORY_FORUMS"
    )
}

/// Identifies a validated User definition within exactly one account.
///
/// Construct through [`LabelDefinition::user_label`] or reconstruct a trusted
/// persisted/provider User classification through [`Self::from_classified_id`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserLabel {
    account: AccountId,
    id: LabelId,
}
impl UserLabel {
    /// Reconstructs an account-bound User target without fabricating a label name.
    ///
    /// The caller must already have trusted persisted or provider classification
    /// as User. This does not infer kind from the ID, prove live provider kind or
    /// existence, or replace fresh target verification before dispatch.
    ///
    /// # Errors
    ///
    /// Rejects known reserved System IDs with [`LabelError::NotUser`]. The
    /// reserved-ID check is defensive, not proof that every other ID is User.
    pub fn from_classified_id(account: AccountId, id: LabelId) -> Result<Self, LabelError> {
        if is_reserved_system_id(id.as_str()) {
            return Err(LabelError::NotUser);
        }
        Ok(Self { account, id })
    }

    /// Returns the account owning this User label.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }
    /// Returns the validated User-label ID.
    #[must_use]
    pub fn id(&self) -> &LabelId {
        &self.id
    }
}

/// Holds complete observed membership for one account, including the empty set.
///
/// IDs are sorted by ASCII bytes; duplicates are errors. Equality is account-
/// sensitive set equality, independent of input order. No partial membership
/// or mutable access is exposed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LabelMembership {
    account: AccountId,
    ids: Vec<LabelId>,
}
impl LabelMembership {
    /// Maximum labels per message, a complete-or-fail product bound.
    pub const MAX_LABELS: usize = 512;

    /// Validates and canonicalizes a complete observed membership set.
    ///
    /// # Errors
    ///
    /// Rejects more than 512 input IDs or any duplicate ID, without truncation.
    pub fn new(account: AccountId, mut ids: Vec<LabelId>) -> Result<Self, LabelError> {
        if ids.len() > Self::MAX_LABELS {
            return Err(LabelError::TooManyLabels);
        }
        ids.sort_unstable();
        if ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(LabelError::DuplicateId);
        }
        Ok(Self { account, ids })
    }
    /// Returns the owning account of this observation.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }
    /// Returns all observed IDs in canonical order.
    #[must_use]
    pub fn ids(&self) -> &[LabelId] {
        &self.ids
    }
    /// Tests membership within this complete observation.
    #[must_use]
    pub fn contains(&self, id: &LabelId) -> bool {
        self.ids.binary_search(id).is_ok()
    }
    pub(crate) fn contains_system(&self, id: &str) -> bool {
        self.ids
            .binary_search_by(|candidate| candidate.as_str().cmp(id))
            .is_ok()
    }
}

/// Distinguishes unavailable provider membership from a complete observed set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservedMembership {
    /// No complete provider observation exists; absence cannot be inferred.
    Unknown,
    /// Complete provider membership, including an explicitly observed empty set.
    Observed(LabelMembership),
}

/// Holds a complete bounded catalog of definitions belonging to one account.
///
/// Definitions are sorted by ID, with duplicate IDs rejected regardless of
/// metadata. Equal names are allowed for ambiguity reconciliation. Overflow is
/// an error; this value never represents a silently truncated provider catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LabelCatalog {
    account: AccountId,
    definitions: Vec<LabelDefinition>,
}
impl LabelCatalog {
    /// Maximum catalog entries, per the T4 product contract.
    pub const MAX_LABELS: usize = 500;

    /// Validates a complete same-account catalog without collapsing duplicates.
    ///
    /// # Errors
    ///
    /// Rejects overflow, cross-account definitions and duplicate IDs.
    pub fn new(
        account: AccountId,
        mut definitions: Vec<LabelDefinition>,
    ) -> Result<Self, LabelError> {
        if definitions.len() > Self::MAX_LABELS {
            return Err(LabelError::TooManyLabels);
        }
        if definitions
            .iter()
            .any(|label| label.account_id() != &account)
        {
            return Err(LabelError::WrongAccount);
        }
        definitions.sort_unstable_by(|left, right| left.id.cmp(&right.id));
        if definitions.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(LabelError::DuplicateId);
        }
        Ok(Self {
            account,
            definitions,
        })
    }
    /// Returns the account whose catalog was observed.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }
    /// Returns every definition in canonical ID order.
    #[must_use]
    pub fn definitions(&self) -> &[LabelDefinition] {
        &self.definitions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(value: &str) -> AccountId {
        AccountId::new(value).expect("valid synthetic value")
    }
    fn id(value: &str) -> LabelId {
        LabelId::new(value).expect("valid synthetic value")
    }
    fn definition(owner: &str, value: &str, name: &str, kind: LabelKind) -> LabelDefinition {
        LabelDefinition::new(
            account(owner),
            id(value),
            LabelName::new(name).expect("valid synthetic value"),
            kind,
        )
        .expect("valid synthetic value")
    }

    // Contract: URL-segment defense and exact byte-preserving bounded names.
    // Regression: path injection, character-count bounds or Unicode normalization.
    #[test]
    fn identifiers_and_names_preserve_only_valid_bounded_bytes() {
        for invalid in [
            "",
            ".",
            "..",
            "Label/a",
            "Label%2F1",
            "a?b",
            "a#b",
            "a b",
            "é",
            "a\n",
        ] {
            assert_eq!(LabelId::new(invalid), Err(LabelError::InvalidId));
        }
        for valid in ["INBOX", "CATEGORY_PERSONAL", "Label_123-a"] {
            assert_eq!(id(valid).as_str(), valid);
        }
        assert!(LabelId::new("a".repeat(256)).is_ok());
        assert_eq!(LabelId::new("a".repeat(257)), Err(LabelError::InvalidId));
        assert_eq!(LabelName::new(""), Err(LabelError::InvalidName));
        assert!(LabelName::new("é".repeat(512)).is_ok());
        assert_eq!(
            LabelName::new("é".repeat(513)),
            Err(LabelError::InvalidName)
        );
        let exact = " \u{001b}[31mé\u{0000} ";
        assert_eq!(
            LabelName::new(exact)
                .expect("valid synthetic value")
                .as_str()
                .as_bytes(),
            exact.as_bytes()
        );
        assert_ne!(
            LabelName::new("é").expect("valid synthetic value"),
            LabelName::new("e\u{0301}").expect("valid synthetic value")
        );
    }

    // Contract: only provider-typed User definitions produce account-bound targets.
    // Regression: system CRUD via a string ID or a misclassified reserved system ID.
    #[test]
    fn user_targets_exclude_system_definitions_and_redact_metadata() {
        for system in ["INBOX", "SENT", "CATEGORY_SOCIAL"] {
            assert_eq!(
                UserLabel::from_classified_id(account("owner-sentinel"), id(system)),
                Err(LabelError::NotUser)
            );
            assert_eq!(
                LabelDefinition::new(
                    account("owner-sentinel"),
                    id(system),
                    LabelName::new("label-name-sentinel").expect("valid synthetic value"),
                    LabelKind::User
                ),
                Err(LabelError::NotUser)
            );
        }
        let system = definition(
            "owner-sentinel",
            "future-system",
            "label-name-sentinel",
            LabelKind::System,
        );
        assert_eq!(system.user_label(), Err(LabelError::NotUser));
        let user = definition(
            "owner-sentinel",
            "Label_id-sentinel",
            "label-name-sentinel",
            LabelKind::User,
        );
        let target = user.user_label().expect("valid synthetic value");
        assert_eq!(target.account_id().as_str(), "owner-sentinel");
        assert_eq!(target.id().as_str(), "Label_id-sentinel");
        for output in [
            format!("{user:?}"),
            format!("{target:?}"),
            format!("{system:?}"),
            LabelError::NotUser.to_string(),
        ] {
            for sentinel in [
                "owner-sentinel",
                "id-sentinel",
                "name-sentinel",
                "future-system",
            ] {
                assert!(!output.contains(sentinel));
            }
        }
    }

    // Contract: complete-or-fail membership, canonical set equality and distinct Unknown.
    // Regression: truncation, duplicate collapse or Unknown becoming empty observation.
    #[test]
    fn membership_is_complete_bounded_and_order_independent() {
        let first = LabelMembership::new(account("owner"), vec![id("b"), id("a")])
            .expect("valid synthetic value");
        let second = LabelMembership::new(account("owner"), vec![id("a"), id("b")])
            .expect("valid synthetic value");
        assert_eq!(first, second);
        assert_eq!(
            first.ids().iter().map(LabelId::as_str).collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert!(first.contains(&id("a")));
        assert!(!first.contains(&id("c")));
        assert_eq!(
            LabelMembership::new(account("owner"), vec![id("a"), id("a")]),
            Err(LabelError::DuplicateId)
        );
        let ids: Vec<_> = (0..512).map(|i| id(&format!("Label_{i}"))).collect();
        assert_eq!(
            LabelMembership::new(account("owner"), ids.clone())
                .expect("valid synthetic value")
                .ids()
                .len(),
            512
        );
        let mut overflow = ids;
        overflow.push(id("extra"));
        assert_eq!(
            LabelMembership::new(account("owner"), overflow),
            Err(LabelError::TooManyLabels)
        );
        let empty = LabelMembership::new(account("owner"), vec![]).expect("valid synthetic value");
        assert_ne!(
            ObservedMembership::Unknown,
            ObservedMembership::Observed(empty)
        );
        assert_ne!(
            first,
            LabelMembership::new(account("other"), vec![id("a"), id("b")])
                .expect("valid synthetic value")
        );
    }

    // Contract: full same-account catalog; duplicate names remain available for ambiguity checks.
    // Regression: guessed ownership, name-based deduplication or catalog truncation.
    #[test]
    fn catalog_preserves_ambiguous_names_but_rejects_invalid_collections() {
        let a = definition("owner", "a", "same", LabelKind::User);
        let b = definition("owner", "b", "same", LabelKind::User);
        let catalog = LabelCatalog::new(account("owner"), vec![b.clone(), a.clone()])
            .expect("valid synthetic value");
        assert_eq!(
            catalog
                .definitions()
                .iter()
                .map(|value| value.id().as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert_eq!(
            catalog,
            LabelCatalog::new(account("owner"), vec![a.clone(), b]).expect("valid synthetic value")
        );
        assert_eq!(
            LabelCatalog::new(account("owner"), vec![a.clone(), a.clone()]),
            Err(LabelError::DuplicateId)
        );
        assert_eq!(
            LabelCatalog::new(account("other"), vec![a]),
            Err(LabelError::WrongAccount)
        );
        assert!(LabelCatalog::new(account("owner"), vec![]).is_ok());
        let labels: Vec<_> = (0..500)
            .map(|i| definition("owner", &format!("Label_{i}"), "same", LabelKind::User))
            .collect();
        assert_eq!(
            LabelCatalog::new(account("owner"), labels.clone())
                .expect("valid synthetic value")
                .definitions()
                .len(),
            500
        );
        let mut overflow = labels;
        overflow.push(definition("owner", "extra", "same", LabelKind::User));
        assert_eq!(
            LabelCatalog::new(account("owner"), overflow),
            Err(LabelError::TooManyLabels)
        );
    }
}
