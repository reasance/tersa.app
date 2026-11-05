// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Validates bounded command/undo ownership before deriving retention pins.
//!
//! This consumes target and touched-state relationships, not the potentially
//! much larger per-item reconciliation membership. Queue transitions stay P5c.

use crate::cached::sql_error;
use rusqlite::Connection;
use std::collections::{HashMap, HashSet};
use tersa_application::{
    command::{MAX_PENDING_COMMANDS, MAX_PENDING_TARGET_REFERENCES},
    mailbox_state::TriageStoreError as Error,
};
use tersa_domain::{
    command::{DesiredMailboxState, MailboxCommandId, MailboxField},
    label::{LabelId, UserLabel},
    mailbox::{AccountId, MessageId},
};

struct Header {
    kind: i64,
    status: i64,
    targets: usize,
}
struct TouchedState {
    field: MailboxField,
    desired: bool,
    pre: Option<bool>,
    post: Option<bool>,
    expected: Option<bool>,
}

fn bit(row: &rusqlite::Row<'_>, index: usize) -> Result<Option<bool>, Error> {
    match row.get::<_, i64>(index).map_err(sql_error)? {
        -1 => Ok(None),
        0 => Ok(Some(false)),
        1 => Ok(Some(true)),
        _ => Err(Error::Corrupt),
    }
}
fn headers(connection: &Connection, account: &AccountId) -> Result<HashMap<String, Header>, Error> {
    let mut statement = connection.prepare(
        "SELECT CASE WHEN typeof(command_id) = 'text' AND length(CAST(command_id AS BLOB)) BETWEEN 1 AND 256 THEN command_id END,
         CASE WHEN typeof(kind) = 'integer' AND kind BETWEEN 0 AND 4 THEN kind END,
         CASE WHEN typeof(status) = 'integer' AND status BETWEEN 0 AND 7 THEN status END,
         CASE WHEN typeof(revision) = 'blob' AND length(revision) = 8 THEN revision END,
         CASE WHEN typeof(automatic_attempts) = 'integer' AND automatic_attempts BETWEEN 0 AND 3 THEN automatic_attempts END,
         CASE WHEN typeof(fifo) = 'integer' AND fifo >= 1 THEN fifo END,
         CASE WHEN label_id IS NULL THEN NULL WHEN typeof(label_id) = 'text' AND length(CAST(label_id AS BLOB)) BETWEEN 1 AND 256 THEN label_id ELSE zeroblob(0) END,
         CASE WHEN label_name IS NULL THEN NULL WHEN typeof(label_name) = 'text' AND length(CAST(label_name AS BLOB)) BETWEEN 1 AND 1024 THEN label_name ELSE zeroblob(0) END
         FROM mailbox_commands LIMIT 34").map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    let mut result = HashMap::new();
    let mut fifo = HashSet::new();
    while let Some(row) = rows.next().map_err(sql_error)? {
        if result.len() == MAX_PENDING_COMMANDS + 1 {
            return Err(Error::Corrupt);
        }
        let id = row.get::<_, String>(0).map_err(sql_error)?;
        MailboxCommandId::new(id.clone()).map_err(|_error| Error::Corrupt)?;
        let kind = row.get(1).map_err(sql_error)?;
        let status = row.get(2).map_err(sql_error)?;
        let _: Vec<u8> = row.get(3).map_err(sql_error)?;
        let attempts: i64 = row.get(4).map_err(sql_error)?;
        if status == 0 && attempts != 0 {
            return Err(Error::Corrupt);
        }
        if !fifo.insert(row.get::<_, i64>(5).map_err(sql_error)?) {
            return Err(Error::Corrupt);
        }
        let label: Option<String> = row.get(6).map_err(sql_error)?;
        let name: Option<String> = row.get(7).map_err(sql_error)?;
        if let Some(label) = &label {
            UserLabel::from_classified_id(
                account.clone(),
                LabelId::new(label.clone()).map_err(|_error| Error::Corrupt)?,
            )
            .map_err(|_error| Error::Corrupt)?;
        }
        if let Some(name) = &name {
            tersa_domain::label::LabelName::new(name.clone()).map_err(|_error| Error::Corrupt)?;
        }
        if !matches!(
            (kind, label.is_some(), name.is_some()),
            (0 | 1, false, false) | (2, false, true) | (3, true, true) | (4, true, false)
        ) {
            return Err(Error::Corrupt);
        }
        if result
            .insert(
                id,
                Header {
                    kind,
                    status,
                    targets: 0,
                },
            )
            .is_some()
        {
            return Err(Error::Corrupt);
        }
    }
    if result.values().filter(|header| header.status < 4).count() > MAX_PENDING_COMMANDS {
        return Err(Error::Corrupt);
    }
    Ok(result)
}
fn undo(
    connection: &Connection,
    headers: &HashMap<String, Header>,
) -> Result<Option<String>, Error> {
    let mut statement = connection.prepare("SELECT CASE WHEN typeof(singleton) = 'integer' AND singleton = 1 THEN singleton END, CASE WHEN typeof(command_id) = 'text' AND length(CAST(command_id AS BLOB)) BETWEEN 1 AND 256 THEN command_id END FROM mailbox_undo LIMIT 2").map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    let id = if let Some(row) = rows.next().map_err(sql_error)? {
        let _: i64 = row.get(0).map_err(sql_error)?;
        let id: String = row.get(1).map_err(sql_error)?;
        if !headers
            .get(&id)
            .is_some_and(|header| header.kind == 0 && header.status == 4)
        {
            return Err(Error::Corrupt);
        }
        Some(id)
    } else {
        None
    };
    if rows.next().map_err(sql_error)?.is_some() {
        return Err(Error::Corrupt);
    }
    if headers
        .iter()
        .any(|(key, header)| header.status >= 4 && Some(key) != id.as_ref())
    {
        return Err(Error::Corrupt);
    }
    Ok(id)
}

type ItemKey = (String, MessageId);
fn items(
    connection: &Connection,
    headers: &mut HashMap<String, Header>,
) -> Result<HashMap<ItemKey, Option<i64>>, Error> {
    let mut statement = connection.prepare(
        "SELECT CASE WHEN typeof(command_id) = 'text' AND length(CAST(command_id AS BLOB)) BETWEEN 1 AND 256 THEN command_id END,
         CASE WHEN typeof(message_id) = 'text' AND length(CAST(message_id AS BLOB)) BETWEEN 1 AND 256 THEN message_id END,
         CASE WHEN outcome IS NULL THEN -1 WHEN typeof(outcome) = 'integer' AND outcome BETWEEN 0 AND 2 THEN outcome END,
         CASE WHEN observation IS NULL THEN -1 WHEN typeof(observation) = 'integer' AND observation IN (0,1) THEN observation END,
         CASE WHEN typeof(dispatch_selected) = 'integer' AND dispatch_selected IN (0,1) THEN dispatch_selected END
         FROM command_items LIMIT 5097").map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    let mut result = HashMap::new();
    let mut pending = 0;
    while let Some(row) = rows.next().map_err(sql_error)? {
        if result.len() == MAX_PENDING_TARGET_REFERENCES + 1000 {
            return Err(Error::Corrupt);
        }
        let command: String = row.get(0).map_err(sql_error)?;
        let message = MessageId::new(row.get::<_, String>(1).map_err(sql_error)?)
            .map_err(|_error| Error::Corrupt)?;
        let header = headers.get_mut(&command).ok_or(Error::Corrupt)?;
        if header.kind >= 2 || header.targets == 1000 {
            return Err(Error::Corrupt);
        }
        header.targets += 1;
        if header.status < 4 {
            pending += 1;
        }
        if pending > MAX_PENDING_TARGET_REFERENCES {
            return Err(Error::Corrupt);
        }
        let outcome: i64 = row.get(2).map_err(sql_error)?;
        if header.status == 4 && outcome != 0 {
            return Err(Error::Corrupt);
        }
        let _: i64 = row.get(3).map_err(sql_error)?;
        let _: i64 = row.get(4).map_err(sql_error)?;
        if result
            .insert(
                (command, message),
                if outcome == -1 { None } else { Some(outcome) },
            )
            .is_some()
        {
            return Err(Error::Corrupt);
        }
    }
    if headers
        .values()
        .any(|header| header.kind < 2 && header.targets == 0)
    {
        return Err(Error::Corrupt);
    }
    Ok(result)
}

fn fields(
    connection: &Connection,
    account: &AccountId,
    items: &HashMap<ItemKey, Option<i64>>,
) -> Result<HashMap<ItemKey, Vec<TouchedState>>, Error> {
    let mut statement = connection.prepare(
        "SELECT CASE WHEN typeof(command_id) = 'text' AND length(CAST(command_id AS BLOB)) BETWEEN 1 AND 256 THEN command_id END,
         CASE WHEN typeof(message_id) = 'text' AND length(CAST(message_id AS BLOB)) BETWEEN 1 AND 256 THEN message_id END,
         CASE WHEN typeof(field_id) = 'text' AND length(CAST(field_id AS BLOB)) BETWEEN 1 AND 256 THEN field_id END,
         CASE WHEN typeof(user_label) = 'integer' AND user_label IN (0,1) THEN user_label END,
         CASE WHEN typeof(desired) = 'integer' AND desired IN (0,1) THEN desired END,
         CASE WHEN pre_state IS NULL THEN -1 WHEN typeof(pre_state) = 'integer' AND pre_state IN (0,1) THEN pre_state END,
         CASE WHEN post_state IS NULL THEN -1 WHEN typeof(post_state) = 'integer' AND post_state IN (0,1) THEN post_state END,
         CASE WHEN expected_post_state IS NULL THEN -1 WHEN typeof(expected_post_state) = 'integer' AND expected_post_state IN (0,1) THEN expected_post_state END
         FROM command_fields LIMIT 10193").map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    let mut result: HashMap<ItemKey, Vec<TouchedState>> = HashMap::new();
    let mut count = 0;
    while let Some(row) = rows.next().map_err(sql_error)? {
        if count == 10192 {
            return Err(Error::Corrupt);
        }
        count += 1;
        let key = (
            row.get::<_, String>(0).map_err(sql_error)?,
            MessageId::new(row.get::<_, String>(1).map_err(sql_error)?)
                .map_err(|_error| Error::Corrupt)?,
        );
        if !items.contains_key(&key) {
            return Err(Error::Corrupt);
        }
        let id: String = row.get(2).map_err(sql_error)?;
        let field = if row.get::<_, i64>(3).map_err(sql_error)? == 1 {
            MailboxField::UserLabel(
                UserLabel::from_classified_id(
                    account.clone(),
                    LabelId::new(id).map_err(|_error| Error::Corrupt)?,
                )
                .map_err(|_error| Error::Corrupt)?,
            )
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
        let values = result.entry(key).or_default();
        if values.len() == 2 {
            return Err(Error::Corrupt);
        }
        values.push(TouchedState {
            field,
            desired: bit(row, 4)?.ok_or(Error::Corrupt)?,
            pre: bit(row, 5)?,
            post: bit(row, 6)?,
            expected: bit(row, 7)?,
        });
    }
    Ok(result)
}

pub(crate) fn read(
    connection: &Connection,
    account: &AccountId,
) -> Result<HashSet<MessageId>, Error> {
    let mut headers = headers(connection, account)?;
    let _undo = undo(connection, &headers)?;
    let items = items(connection, &mut headers)?;
    let fields = fields(connection, account, &items)?;
    let mut pins = HashSet::new();
    for (key, _outcome) in items {
        let header = headers.get(&key.0).ok_or(Error::Corrupt)?;
        let values = fields.get(&key).ok_or(Error::Corrupt)?;
        if header.status == 4 && values.iter().any(|v| v.post != Some(v.desired)) {
            return Err(Error::Corrupt);
        }
        DesiredMailboxState::from_touched_fields(
            account.clone(),
            values
                .iter()
                .map(|v| (v.field.clone(), v.desired))
                .collect(),
        )
        .map_err(|_error| Error::Corrupt)?;
        for (role, required) in [
            (0, header.status == 4),
            (1, header.status == 4),
            (2, header.kind == 1),
        ] {
            let selected: Vec<_> = values
                .iter()
                .filter_map(|v| {
                    let bit = match role {
                        0 => v.pre,
                        1 => v.post,
                        _ => v.expected,
                    };
                    bit.map(|bit| (v.field.clone(), bit))
                })
                .collect();
            if (required && selected.len() != values.len())
                || (!selected.is_empty() && selected.len() != values.len())
                || (role == 2 && header.kind != 1 && !selected.is_empty())
            {
                return Err(Error::Corrupt);
            }
            if !selected.is_empty() {
                DesiredMailboxState::from_touched_fields(account.clone(), selected)
                    .map_err(|_error| Error::Corrupt)?;
            }
        }
        pins.insert(key.1);
    }
    Ok(pins)
}
