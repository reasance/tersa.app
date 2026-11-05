// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Bounded decoding of durable command intent and evidence, without invented observations.

use crate::cached::sql_error;
use rusqlite::{Connection, Row, types::ValueRef};
use tersa_application::{
    command::{
        CommandCategory, CommandCounts, CommandItemProgress, CommandKey, CommandProgress,
        CommandSnapshot, CommandStamp, LabelItemProgress, MAX_PENDING_COMMANDS,
        MAX_TERMINAL_SUMMARIES, RetryAuthorization, TerminalCommandSummary, UndoCandidate,
    },
    mailbox_state::{MessageKey, RemoteMessageState, TriageStoreError as Error},
};
use tersa_domain::{
    account::AccountCapability,
    command::{
        CommandItemOutcome, CompensationBatch, ConditionalCompensation, DesiredMailboxState,
        MailboxCommand, MailboxCommandId, MailboxCommandKind, MailboxCommandStatus, MailboxField,
        MessageAction, MessageCompensation, MessageTargets,
    },
    label::{
        LabelDefinition, LabelId, LabelKind, LabelMembership, LabelName, ObservedMembership,
        UserLabel,
    },
    mailbox::{AccountId, MessageId},
};

pub(super) fn text(row: &Row<'_>, index: usize, max: usize) -> Result<Option<String>, Error> {
    match row.get_ref(index).map_err(sql_error)? {
        ValueRef::Null => Ok(None),
        ValueRef::Text(bytes) if (1..=max).contains(&bytes.len()) => std::str::from_utf8(bytes)
            .map(|s| Some(s.to_owned()))
            .map_err(|_error| Error::Corrupt),
        _ => Err(Error::Corrupt),
    }
}
pub(super) fn integer(row: &Row<'_>, index: usize, max: i64) -> Result<Option<i64>, Error> {
    match row.get_ref(index).map_err(sql_error)? {
        ValueRef::Null => Ok(None),
        ValueRef::Integer(value) if (0..=max).contains(&value) => Ok(Some(value)),
        _ => Err(Error::Corrupt),
    }
}
fn bit(row: &Row<'_>, index: usize) -> Result<Option<bool>, Error> {
    Ok(integer(row, index, 1)?.map(|v| v == 1))
}
pub(super) fn revision(row: &Row<'_>, index: usize) -> Result<Option<u64>, Error> {
    match row.get_ref(index).map_err(sql_error)? {
        ValueRef::Null => Ok(None),
        ValueRef::Blob(bytes) => Ok(Some(u64::from_be_bytes(
            bytes.try_into().map_err(|_error| Error::Corrupt)?,
        ))),
        _ => Err(Error::Corrupt),
    }
}
pub(super) fn status(code: i64) -> Result<MailboxCommandStatus, Error> {
    use MailboxCommandStatus::{
        Abandoned, Ambiguous, Cancelled, Complete, Dispatching, NeedsAttention, Partial, Queued,
    };
    match code {
        0 => Ok(Queued),
        1 => Ok(Dispatching),
        2 => Ok(Ambiguous),
        3 => Ok(NeedsAttention),
        4 => Ok(Complete),
        5 => Ok(Partial),
        6 => Ok(Cancelled),
        7 => Ok(Abandoned),
        _ => Err(Error::Corrupt),
    }
}
pub(super) fn status_code(value: MailboxCommandStatus) -> i64 {
    use MailboxCommandStatus::{
        Abandoned, Ambiguous, Cancelled, Complete, Dispatching, NeedsAttention, Partial, Queued,
    };
    match value {
        Queued => 0,
        Dispatching => 1,
        Ambiguous => 2,
        NeedsAttention => 3,
        Complete => 4,
        Partial => 5,
        Cancelled => 6,
        Abandoned => 7,
    }
}
pub(super) fn field_id(value: &MailboxField) -> &str {
    match value {
        MailboxField::Unread => "UNREAD",
        MailboxField::Starred => "STARRED",
        MailboxField::Inbox => "INBOX",
        MailboxField::Trash => "TRASH",
        MailboxField::Spam => "SPAM",
        MailboxField::UserLabel(label) => label.id().as_str(),
    }
}
fn user(account: &AccountId, id: String) -> Result<UserLabel, Error> {
    UserLabel::from_classified_id(
        account.clone(),
        LabelId::new(id).map_err(|_error| Error::Corrupt)?,
    )
    .map_err(|_error| Error::Corrupt)
}
fn definition(
    account: &AccountId,
    id: Option<String>,
    name: Option<String>,
) -> Result<Option<LabelDefinition>, Error> {
    match (id, name) {
        (None, None) => Ok(None),
        (Some(id), Some(name)) => LabelDefinition::new(
            account.clone(),
            LabelId::new(id).map_err(|_error| Error::Corrupt)?,
            LabelName::new(name).map_err(|_error| Error::Corrupt)?,
            LabelKind::User,
        )
        .map(Some)
        .map_err(|_error| Error::Corrupt),
        _ => Err(Error::Corrupt),
    }
}

pub(super) struct Header {
    pub id: MailboxCommandId,
    pub revision: u64,
    pub fifo: i64,
    pub kind: i64,
    pub status: MailboxCommandStatus,
    pub attempts: u8,
    pub retry: Option<u64>,
    pub duplicate_risk: bool,
    pub dispatch: Option<u64>,
    pub authorization: Option<i64>,
    pub guard: Option<u64>,
    pub fact: Option<i64>,
    pub dispatch_label: Option<LabelDefinition>,
    pub label_observation: Option<bool>,
    pub source: Option<(MailboxCommandId, u64)>,
    pub failure: Option<i64>,
    pub label: Option<UserLabel>,
    pub name: Option<LabelName>,
    pub label_progress: i64,
    pub matches: Option<i64>,
    pub observed_label: Option<LabelDefinition>,
}
impl Header {
    pub fn stamp(&self, account: &AccountId) -> CommandStamp {
        CommandStamp::new(
            CommandKey::new(account.clone(), self.id.clone()),
            self.revision,
        )
    }
    #[expect(
        clippy::too_many_lines,
        reason = "The fixed durable header is decoded and validated as one closed record"
    )]
    fn decode(row: &Row<'_>, account: &AccountId) -> Result<Self, Error> {
        let started = bit(row, 8)?.ok_or(Error::Corrupt)?;
        let source_id = text(row, 16, 256)?
            .map(MailboxCommandId::new)
            .transpose()
            .map_err(|_error| Error::Corrupt)?;
        let source_revision = revision(row, 17)?;
        let header = Self {
            id: MailboxCommandId::new(text(row, 0, 256)?.ok_or(Error::Corrupt)?)
                .map_err(|_error| Error::Corrupt)?,
            revision: revision(row, 1)?.ok_or(Error::Corrupt)?,
            fifo: integer(row, 2, i64::MAX)?
                .filter(|v| *v > 0)
                .ok_or(Error::Corrupt)?,
            kind: integer(row, 3, 4)?.ok_or(Error::Corrupt)?,
            status: status(integer(row, 4, 7)?.ok_or(Error::Corrupt)?)?,
            attempts: u8::try_from(integer(row, 5, 3)?.ok_or(Error::Corrupt)?)
                .map_err(|_error| Error::Corrupt)?,
            retry: revision(row, 6)?,
            duplicate_risk: bit(row, 7)?.ok_or(Error::Corrupt)?,
            dispatch: revision(row, 9)?,
            authorization: integer(row, 10, 1)?,
            guard: revision(row, 11)?,
            fact: integer(row, 12, 6)?,
            dispatch_label: definition(account, text(row, 13, 256)?, text(row, 14, 1024)?)?,
            label_observation: bit(row, 15)?,
            source: match (source_id, source_revision) {
                (None, None) => None,
                (Some(id), Some(rev)) => Some((id, rev)),
                _ => return Err(Error::Corrupt),
            },
            failure: integer(row, 18, 2)?,
            label: text(row, 19, 256)?.map(|s| user(account, s)).transpose()?,
            name: text(row, 20, 1024)?
                .map(LabelName::new)
                .transpose()
                .map_err(|_error| Error::Corrupt)?,
            label_progress: integer(row, 21, 2)?.ok_or(Error::Corrupt)?,
            matches: integer(row, 22, 2)?,
            observed_label: definition(account, text(row, 23, 256)?, text(row, 24, 1024)?)?,
        };
        if !matches!(
            (header.kind, header.label.is_some(), header.name.is_some()),
            (0 | 1, false, false) | (2, false, true) | (3, true, true) | (4, true, false)
        ) || started != header.dispatch.is_some()
            || started != header.authorization.is_some()
            || (!started
                && (header.fact.is_some()
                    || header.attempts != 0
                    || header.guard.is_some()
                    || header.duplicate_risk))
            || (header.status == MailboxCommandStatus::Queued && (started || header.attempts != 0))
            || (header.status == MailboxCommandStatus::Dispatching
                && (!started || header.dispatch != Some(header.revision) || header.fact.is_some()))
            || (header.status == MailboxCommandStatus::Ambiguous && !started)
            || header.dispatch.is_some_and(|rev| rev > header.revision)
            || header
                .guard
                .is_some_and(|rev| header.kind != 1 || Some(rev) > header.dispatch)
            || (header.kind == 1
                && (header.source.is_none() || (started && header.guard.is_none())))
            || (header.kind != 1 && header.source.is_some())
            || header
                .source
                .as_ref()
                .is_some_and(|(id, _)| id == &header.id)
            || header.retry.is_some_and(|rev| {
                rev != header.revision
                    || !matches!(
                        header.status,
                        MailboxCommandStatus::Ambiguous | MailboxCommandStatus::NeedsAttention
                    )
            })
            || (header.fact == Some(1)) != header.dispatch_label.is_some()
            || (header.dispatch_label.is_some() && header.kind != 2)
            || header
                .dispatch_label
                .as_ref()
                .is_some_and(|l| Some(l.name()) != header.name.as_ref())
            || header
                .fact
                .is_some_and(|f| (f == 0 && header.kind > 1) || (f == 2 && header.kind < 3))
            || (header.kind != 2 && (header.matches.is_some() || header.duplicate_risk))
            || (header.kind < 2 && header.label_progress != 0)
            || (header.authorization == Some(0) && header.attempts == 0)
            || (header.kind == 2
                && (header.label_observation.is_some()
                    || (header.matches == Some(1)) != header.observed_label.is_some()))
            || (header.kind >= 3
                && header.label_observation == Some(true)
                && header.observed_label.is_none())
            || (header.kind >= 3
                && header
                    .observed_label
                    .as_ref()
                    .is_some_and(|l| header.label.as_ref().is_none_or(|v| v.id() != l.id())))
            || (header.kind >= 3
                && header.observed_label.is_some() != (header.label_observation == Some(true)))
        {
            return Err(Error::Corrupt);
        }
        Ok(header)
    }
}
const HEADER_SQL: &str = "SELECT command_id,revision,fifo,kind,status,automatic_attempts,retry_revision,duplicate_risk,dispatch_started,dispatch_revision,dispatch_authorization,compensation_guard_revision,dispatch_fact,dispatch_label_id,dispatch_label_name,label_observation,undo_source_id,undo_source_revision,reconciliation_failure,label_id,label_name,label_progress,create_matches,observed_label_id,observed_label_name FROM mailbox_commands ORDER BY fifo LIMIT 34";
pub(super) fn headers(connection: &Connection, account: &AccountId) -> Result<Vec<Header>, Error> {
    let mut statement = connection.prepare(HEADER_SQL).map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    let mut result = Vec::new();
    while let Some(row) = rows.next().map_err(sql_error)? {
        if result.len() == MAX_PENDING_COMMANDS + 1 {
            return Err(Error::Corrupt);
        }
        result.push(Header::decode(row, account)?);
    }
    Ok(result)
}

pub(super) struct Item {
    pub id: MessageId,
    pub desired: DesiredMailboxState,
    pub pre: Option<DesiredMailboxState>,
    pub post: Option<DesiredMailboxState>,
    pub expected: Option<DesiredMailboxState>,
    pub outcome: Option<CommandItemOutcome>,
    pub observation: Option<RemoteMessageState>,
    pub selected: bool,
}
pub(super) struct Body {
    pub header: Header,
    pub items: Vec<Item>,
    pub command: MailboxCommand,
}
fn touched(
    account: &AccountId,
    fields: Vec<(MailboxField, bool)>,
    required: bool,
    count: usize,
) -> Result<Option<DesiredMailboxState>, Error> {
    if fields.is_empty() && !required {
        return Ok(None);
    }
    if fields.len() != count {
        return Err(Error::Corrupt);
    }
    DesiredMailboxState::from_touched_fields(account.clone(), fields)
        .map(Some)
        .map_err(|_error| Error::Corrupt)
}
fn fields(
    connection: &Connection,
    account: &AccountId,
    command: &str,
    message: &str,
) -> Result<[Option<DesiredMailboxState>; 4], Error> {
    let mut statement = connection.prepare("SELECT field_id,user_label,desired,pre_state,post_state,expected_post_state FROM command_fields WHERE command_id = ?1 AND message_id = ?2 LIMIT 3").map_err(sql_error)?;
    let mut rows = statement.query([command, message]).map_err(sql_error)?;
    let mut values: [Vec<(MailboxField, bool)>; 4] = std::array::from_fn(|_| Vec::new());
    let mut count = 0;
    while let Some(row) = rows.next().map_err(sql_error)? {
        if count == 2 {
            return Err(Error::Corrupt);
        }
        count += 1;
        let id = text(row, 0, 256)?.ok_or(Error::Corrupt)?;
        let field = if bit(row, 1)?.ok_or(Error::Corrupt)? {
            MailboxField::UserLabel(user(account, id)?)
        } else {
            match id.as_str() {
                "UNREAD" => MailboxField::Unread,
                "STARRED" => MailboxField::Starred,
                "INBOX" => MailboxField::Inbox,
                "TRASH" => MailboxField::Trash,
                "SPAM" => MailboxField::Spam,
                _ => return Err(Error::Corrupt),
            }
        };
        for (i, values) in values.iter_mut().enumerate() {
            if let Some(bit) = bit(row, i + 2)? {
                values.push((field.clone(), bit));
            }
        }
    }
    let [desired, pre, post, expected] = values;
    Ok([
        touched(account, desired, true, count)?,
        touched(account, pre, false, count)?,
        touched(account, post, false, count)?,
        touched(account, expected, false, count)?,
    ])
}
fn memberships(
    connection: &Connection,
    account: &AccountId,
    command: &str,
    message: &str,
    observed: Option<i64>,
) -> Result<Option<RemoteMessageState>, Error> {
    let mut statement = connection.prepare("SELECT label_id FROM command_item_memberships WHERE command_id = ?1 AND message_id = ?2 ORDER BY label_id LIMIT 513").map_err(sql_error)?;
    let mut rows = statement.query([command, message]).map_err(sql_error)?;
    let mut values = Vec::new();
    while let Some(row) = rows.next().map_err(sql_error)? {
        if values.len() == LabelMembership::MAX_LABELS || observed != Some(1) {
            return Err(Error::Corrupt);
        }
        values.push(
            LabelId::new(text(row, 0, 256)?.ok_or(Error::Corrupt)?)
                .map_err(|_error| Error::Corrupt)?,
        );
    }
    match observed {
        None => Ok(None),
        Some(0) => Ok(Some(RemoteMessageState::Missing)),
        Some(1) => Ok(Some(RemoteMessageState::Known(
            LabelMembership::new(account.clone(), values).map_err(|_error| Error::Corrupt)?,
        ))),
        _ => Err(Error::Corrupt),
    }
}
fn action(desired: &DesiredMailboxState) -> Result<MessageAction, Error> {
    use MailboxField::{Inbox, Spam, Starred, Trash, Unread, UserLabel};
    let bits: Vec<_> = desired
        .memberships()
        .iter()
        .map(|v| (v.field(), v.is_present()))
        .collect();
    match bits.as_slice() {
        [(Unread, false)] => Ok(MessageAction::Read),
        [(Unread, true)] => Ok(MessageAction::Unread),
        [(Starred, true)] => Ok(MessageAction::Star),
        [(Starred, false)] => Ok(MessageAction::Unstar),
        [(Inbox, false)] => Ok(MessageAction::Archive),
        [(Trash, true), (Inbox, false)] => Ok(MessageAction::Trash),
        [(Trash, false), (Inbox, true)] => Ok(MessageAction::Restore),
        [(Spam, true), (Inbox, false)] => Ok(MessageAction::Spam),
        [(Spam, false), (Inbox, true)] => Ok(MessageAction::ClearSpam),
        [(UserLabel(label), true)] => Ok(MessageAction::ApplyLabel(label.clone())),
        [(UserLabel(label), false)] => Ok(MessageAction::RemoveLabel(label.clone())),
        _ => Err(Error::Corrupt),
    }
}
pub(super) fn no_orphans(connection: &Connection, command: &str) -> Result<(), Error> {
    let bad: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM command_item_memberships AS m WHERE command_id = ?1 AND NOT EXISTS(SELECT 1 FROM command_items AS i WHERE i.command_id = m.command_id AND i.message_id = m.message_id)) OR EXISTS(SELECT 1 FROM command_fields AS f WHERE command_id = ?1 AND NOT EXISTS(SELECT 1 FROM command_items AS i WHERE i.command_id = f.command_id AND i.message_id = f.message_id))",[command],|r| r.get(0)).map_err(sql_error)?;
    if bad { Err(Error::Corrupt) } else { Ok(()) }
}
#[expect(
    clippy::too_many_lines,
    reason = "Reconstructs the complete bounded command and validates cross-row evidence"
)]
pub(super) fn body(
    connection: &Connection,
    account: &AccountId,
    header: Header,
) -> Result<Body, Error> {
    let command_id = header.id.as_str();
    no_orphans(connection, command_id)?;
    let mut statement = connection.prepare("SELECT message_id,outcome,observation,dispatch_selected FROM command_items WHERE command_id = ?1 ORDER BY message_id LIMIT 1001").map_err(sql_error)?;
    let mut rows = statement.query([command_id]).map_err(sql_error)?;
    let mut items = Vec::new();
    while let Some(row) = rows.next().map_err(sql_error)? {
        if items.len() == MessageTargets::MAX_TARGETS || header.kind >= 2 {
            return Err(Error::Corrupt);
        }
        let id = MessageId::new(text(row, 0, 256)?.ok_or(Error::Corrupt)?)
            .map_err(|_error| Error::Corrupt)?;
        let outcome = match integer(row, 1, 2)? {
            None => None,
            Some(0) => Some(CommandItemOutcome::DesiredStateObserved),
            Some(1) => Some(CommandItemOutcome::TargetMissing),
            Some(2) => Some(CommandItemOutcome::Failed),
            _ => return Err(Error::Corrupt),
        };
        let observation = memberships(
            connection,
            account,
            command_id,
            id.as_str(),
            integer(row, 2, 1)?,
        )?;
        let [desired, pre, post, expected] = fields(connection, account, command_id, id.as_str())?;
        let item = Item {
            id,
            desired: desired.ok_or(Error::Corrupt)?,
            pre,
            post,
            expected,
            outcome,
            observation,
            selected: bit(row, 3)?.ok_or(Error::Corrupt)?,
        };
        if (header.kind == 1) != item.expected.is_some()
            || (item.selected && (header.dispatch.is_none() || item.pre.is_none()))
            || (item.outcome == Some(CommandItemOutcome::DesiredStateObserved)
                && (item.pre.is_none() || item.post.as_ref() != Some(&item.desired)))
            || (item.post.is_some() && item.observation.is_none())
        {
            return Err(Error::Corrupt);
        }
        if let Some(RemoteMessageState::Known(labels)) = &item.observation {
            let actual = item
                .desired
                .record_pre_state(&ObservedMembership::Observed(labels.clone()))
                .ok_or(Error::Corrupt)?;
            if item.post.as_ref() != Some(&actual) || item.pre.is_none() {
                return Err(Error::Corrupt);
            }
        } else if item.post.is_some() {
            return Err(Error::Corrupt);
        }
        items.push(item);
    }
    if header.kind < 2 && items.is_empty() {
        return Err(Error::Corrupt);
    }
    if header.dispatch.is_some() && header.kind < 2 && !items.iter().any(|i| i.selected) {
        return Err(Error::Corrupt);
    }
    let capability = AccountCapability::Modify; // Reconstruct intent; this is never current grant authority.
    let id = header.id.clone();
    let command = match header.kind {
        0 => {
            if items.iter().any(|i| i.desired != items[0].desired) {
                return Err(Error::Corrupt);
            }
            MailboxCommand::message_state(
                capability,
                id,
                MessageTargets::new(
                    account.clone(),
                    items.iter().map(|i| i.id.clone()).collect(),
                )
                .map_err(|_error| Error::Corrupt)?,
                &action(&items[0].desired)?,
            )
        }
        1 => MailboxCommand::compensate(
            capability,
            id,
            CompensationBatch::new(
                account.clone(),
                items
                    .iter()
                    .map(|i| {
                        Ok(MessageCompensation::new(
                            i.id.clone(),
                            ConditionalCompensation::new(
                                i.expected.clone().ok_or(Error::Corrupt)?,
                                i.desired.clone(),
                            )
                            .map_err(|_error| Error::Corrupt)?,
                        ))
                    })
                    .collect::<Result<Vec<_>, Error>>()?,
            )
            .map_err(|_error| Error::Corrupt)?,
        ),
        2 => MailboxCommand::create_label(
            capability,
            id,
            account.clone(),
            header.name.clone().ok_or(Error::Corrupt)?,
        ),
        3 => MailboxCommand::rename_label(
            capability,
            id,
            header.label.clone().ok_or(Error::Corrupt)?,
            header.name.clone().ok_or(Error::Corrupt)?,
        ),
        4 => MailboxCommand::delete_label(
            capability,
            id,
            header.label.clone().ok_or(Error::Corrupt)?,
        ),
        _ => return Err(Error::Corrupt),
    }
    .map_err(|_error| Error::Corrupt)?;
    let body = Body {
        header,
        items,
        command,
    };
    validate_body(connection, account, &body)?;
    body.snapshot(account)?;
    Ok(body)
}
fn validate_body(connection: &Connection, account: &AccountId, body: &Body) -> Result<(), Error> {
    let h = &body.header;
    let required = body.items.first().and_then(|i| {
        i.desired.memberships().iter().find_map(|v| {
            if let MailboxField::UserLabel(label) = v.field() {
                Some(label)
            } else {
                None
            }
        })
    });
    if h.kind < 2 {
        if (required.is_none() && (h.label_observation.is_some() || h.observed_label.is_some()))
            || h.observed_label.is_some() != (h.label_observation == Some(true))
            || h.observed_label
                .as_ref()
                .is_some_and(|d| required.is_none_or(|label| label.id() != d.id()))
        {
            return Err(Error::Corrupt);
        }
        for item in &body.items {
            if (item.outcome == Some(CommandItemOutcome::TargetMissing)
                && item.observation != Some(RemoteMessageState::Missing))
                || (item.outcome == Some(CommandItemOutcome::DesiredStateObserved)
                    && !matches!(item.observation, Some(RemoteMessageState::Known(_))))
                || (item.outcome == Some(CommandItemOutcome::Failed)
                    && !matches!(item.observation, Some(RemoteMessageState::Known(_))))
            {
                return Err(Error::Corrupt);
            }
        }
    } else if (h.label_progress == 1
        && match h.kind {
            2 => {
                h.matches != Some(1)
                    || h.observed_label.as_ref().map(LabelDefinition::name) != h.name.as_ref()
            }
            3 => {
                h.label_observation != Some(true)
                    || h.observed_label.as_ref().map(LabelDefinition::name) != h.name.as_ref()
            }
            4 => h.label_observation != Some(false),
            _ => true,
        })
        || (h.label_progress == 2
            && h.fact != Some(6)
            && !(h.kind == 3 && h.label_observation == Some(false)))
    {
        return Err(Error::Corrupt);
    }
    if let MailboxCommandKind::Compensate(batch) = body.command.kind() {
        let (source_id, revision) = h.source.as_ref().ok_or(Error::Corrupt)?;
        let source = headers(connection, account)?
            .into_iter()
            .find(|s| {
                &s.id == source_id
                    && s.kind == 0
                    && s.status == MailboxCommandStatus::Complete
                    && s.revision == *revision
                    && s.fifo < h.fifo
            })
            .ok_or(Error::Corrupt)?;
        let source = self::body(connection, account, source)?;
        let candidate = undo_from_body(account, &source)?;
        if candidate.compensation() != batch {
            return Err(Error::Corrupt);
        }
    }
    Ok(())
}
pub(super) fn undo_from_body(account: &AccountId, body: &Body) -> Result<UndoCandidate, Error> {
    let items = body
        .items
        .iter()
        .map(|i| {
            Ok(MessageCompensation::new(
                i.id.clone(),
                ConditionalCompensation::new(
                    i.post.clone().ok_or(Error::Corrupt)?,
                    i.pre.clone().ok_or(Error::Corrupt)?,
                )
                .map_err(|_error| Error::Corrupt)?,
            ))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    UndoCandidate::new(
        &body.snapshot(account)?,
        CompensationBatch::new(account.clone(), items).map_err(|_error| Error::Corrupt)?,
    )
    .map_err(|_error| Error::Corrupt)
}
impl Body {
    pub fn snapshot(&self, account: &AccountId) -> Result<CommandSnapshot, Error> {
        let progress = if self.header.kind < 2 {
            CommandProgress::Messages(
                self.items
                    .iter()
                    .map(|i| {
                        CommandItemProgress::new(
                            MessageKey::new(account.clone(), i.id.clone()),
                            i.outcome,
                        )
                    })
                    .collect(),
            )
        } else {
            CommandProgress::Label(match self.header.label_progress {
                0 => LabelItemProgress::Pending,
                1 => LabelItemProgress::Complete,
                2 => LabelItemProgress::Failed,
                _ => return Err(Error::Corrupt),
            })
        };
        let stamp = self.header.stamp(account);
        CommandSnapshot::new(
            self.command.clone(),
            stamp.clone(),
            self.header.status,
            self.header.attempts,
            progress,
            self.header
                .retry
                .map(|_| RetryAuthorization::from_store(stamp)),
        )
        .map_err(|_error| Error::Corrupt)
    }
}
pub(super) fn summaries(
    connection: &Connection,
    account: &AccountId,
) -> Result<Vec<(i64, TerminalCommandSummary)>, Error> {
    let mut statement = connection.prepare("SELECT command_id,revision,fifo,status,category,total,satisfied,missing,failed FROM terminal_commands ORDER BY fifo DESC LIMIT 129").map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    let mut result = Vec::new();
    while let Some(row) = rows.next().map_err(sql_error)? {
        if result.len() == MAX_TERMINAL_SUMMARIES {
            return Err(Error::Corrupt);
        }
        let id = MailboxCommandId::new(text(row, 0, 256)?.ok_or(Error::Corrupt)?)
            .map_err(|_error| Error::Corrupt)?;
        let revision = revision(row, 1)?.ok_or(Error::Corrupt)?;
        let fifo = integer(row, 2, i64::MAX)?
            .filter(|v| *v > 0)
            .ok_or(Error::Corrupt)?;
        let status = status(integer(row, 3, 7)?.ok_or(Error::Corrupt)?)?;
        let category = match integer(row, 4, 2)? {
            Some(0) => CommandCategory::MessageState,
            Some(1) => CommandCategory::Compensation,
            Some(2) => CommandCategory::LabelDefinition,
            _ => return Err(Error::Corrupt),
        };
        let count = |index| {
            integer(row, index, 1000)?
                .and_then(|v| u16::try_from(v).ok())
                .ok_or(Error::Corrupt)
        };
        let counts = CommandCounts::from_retained(count(5)?, count(6)?, count(7)?, count(8)?)
            .map_err(|_error| Error::Corrupt)?;
        result.push((
            fifo,
            TerminalCommandSummary::from_retained(
                CommandStamp::new(CommandKey::new(account.clone(), id), revision),
                status,
                counts,
                category,
            )
            .map_err(|_error| Error::Corrupt)?,
        ));
    }
    Ok(result)
}
