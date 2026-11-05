// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Defines the complete v3 layout and allocation-bounded persisted-value validation.
//!
//! Future History/queue slices add transaction methods, not canonical objects.
//! SQL constraints protect ordinary writes. Routine opens inspect bounded
//! singleton metadata; migration validates old rows without fetching body bytes.
//! Later History/command methods must validate their bounded decoded rows.

use rusqlite::Connection;
use tersa_domain::{
    history::HistoryCursor,
    mailbox::{AccountId, MessageId, ThreadId},
};
use zeroize::Zeroizing;

pub(crate) const MIGRATION: &str = include_str!("../migrations/0003_triage.sql");

pub(crate) fn canonical_objects() -> Vec<(String, String, String)> {
    let sql = MIGRATION
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");
    sql.split(';')
        .filter_map(|sql| {
            let words = sql.split_whitespace().collect::<Vec<_>>();
            if words.first() != Some(&"CREATE") {
                return None;
            }
            Some((
                words[1].to_ascii_lowercase(),
                words[2].to_owned(),
                words.join(" "),
            ))
        })
        .collect()
}

fn invalid() -> rusqlite::Error {
    rusqlite::Error::InvalidQuery
}

fn reject_if(connection: &Connection, sql: &str) -> rusqlite::Result<()> {
    let invalid: bool = connection.query_row(sql, [], |row| row.get(0))?;
    if invalid {
        Err(self::invalid())
    } else {
        Ok(())
    }
}

/// Only singleton metadata is inspected during routine ownership validation.
/// No messages, membership, label catalog, item rows or cached bodies are read.
pub(crate) fn validate_metadata(connection: &Connection, version: i64) -> rusqlite::Result<()> {
    reject_if(
        connection,
        "SELECT count(*) != 1 FROM (SELECT singleton FROM account_binding LIMIT 2)",
    )?;
    reject_if(
        connection,
        "SELECT EXISTS(SELECT 1 FROM account_binding WHERE typeof(singleton) != 'integer' OR singleton != 1 OR typeof(account_id) != 'text' OR length(CAST(account_id AS BLOB)) NOT BETWEEN 1 AND 256 OR (broker_subject IS NOT NULL AND (typeof(broker_subject) != 'text' OR length(CAST(broker_subject AS BLOB)) NOT BETWEEN 1 AND 255)) OR (refresh_token IS NOT NULL AND (typeof(refresh_token) != 'text' OR length(CAST(refresh_token AS BLOB)) NOT BETWEEN 1 AND 4096)))",
    )?;
    if version >= 2 {
        reject_if(
            connection,
            "SELECT EXISTS(SELECT 1 FROM account_binding WHERE email_address IS NOT NULL AND (typeof(email_address) != 'text' OR length(CAST(email_address AS BLOB)) NOT BETWEEN 3 AND 320))",
        )?;
    }
    if version != 3 {
        return Ok(());
    }
    reject_if(
        connection,
        "SELECT EXISTS(SELECT 1 FROM account_binding WHERE typeof(capability) != 'integer' OR capability NOT IN (0,1) OR typeof(credential_purpose) != 'integer' OR credential_purpose NOT IN (0,1,2) OR (credential_purpose = 0) != (refresh_token IS NULL) OR (broker_subject IS NULL AND (capability != 0 OR credential_purpose = 2)))",
    )?;
    reject_if(
        connection,
        "SELECT count(*) != 1 FROM (SELECT singleton FROM mailbox_checkpoint LIMIT 2)",
    )?;
    reject_if(
        connection,
        "SELECT EXISTS(SELECT 1 FROM mailbox_checkpoint WHERE typeof(singleton) != 'integer' OR singleton != 1 OR typeof(recovery_required) != 'integer' OR recovery_required NOT IN (0,1) OR typeof(catalog_known) != 'integer' OR catalog_known NOT IN (0,1) OR typeof(next_fifo) != 'integer' OR next_fifo < 1 OR (history_cursor IS NOT NULL AND (typeof(history_cursor) != 'text' OR length(CAST(history_cursor AS BLOB)) NOT BETWEEN 1 AND 32)))",
    )?;
    let mut statement = connection.prepare("SELECT typeof(history_cursor), CASE WHEN typeof(history_cursor) = 'text' AND length(CAST(history_cursor AS BLOB)) BETWEEN 1 AND 32 THEN history_cursor END FROM mailbox_checkpoint WHERE singleton = 1")?;
    let mut rows = statement.query([])?;
    let row = rows.next()?.ok_or_else(invalid)?;
    if row.get::<_, String>(0)? != "null" {
        HistoryCursor::new(row.get::<_, String>(1)?).map_err(|_error| invalid())?;
    }
    Ok(())
}

/// Runs only under the migration writer transaction, before any schema change.
/// Body data never crosses SQL: only type and byte length are checked.
pub(crate) fn validate_migration_rows(
    connection: &Connection,
    account: &AccountId,
    version: i64,
) -> rusqlite::Result<()> {
    validate_metadata(connection, version)?;
    let subject = connection.query_row(
        "SELECT CASE WHEN typeof(broker_subject) = 'text' AND length(CAST(broker_subject AS BLOB)) BETWEEN 1 AND 255 THEN broker_subject END FROM account_binding WHERE singleton = 1", [],
        |row| row.get::<_, Option<String>>(0).map(|value| value.map(Zeroizing::new)),
    )?;
    if subject
        .as_ref()
        .is_some_and(|value| !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)))
    {
        return Err(invalid());
    }
    reject_if(
        connection,
        "SELECT EXISTS(SELECT 1 FROM messages WHERE content IS NOT NULL AND (typeof(content) != 'blob' OR length(content) > 67108864))",
    )?;
    let mut statement = connection.prepare(
        "SELECT CASE WHEN typeof(message_id) = 'text' AND length(CAST(message_id AS BLOB)) BETWEEN 1 AND 256 THEN message_id END,
                CASE WHEN typeof(thread_id) = 'text' AND length(CAST(thread_id AS BLOB)) BETWEEN 1 AND 256 THEN thread_id END,
                CASE WHEN typeof(sender) = 'text' AND length(CAST(sender AS BLOB)) <= 1024 THEN sender END,
                CASE WHEN typeof(subject) = 'text' AND length(CAST(subject AS BLOB)) <= 1024 THEN subject END,
                CASE WHEN typeof(preview) = 'text' AND length(CAST(preview AS BLOB)) <= 1024 THEN preview END,
                CASE WHEN typeof(received_at) = 'integer' AND received_at >= 0 THEN received_at END,
                CASE WHEN typeof(unread) = 'integer' AND unread IN (0,1) THEN unread END
         FROM messages")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        MessageId::new(row.get::<_, String>(0)?).map_err(|_error| invalid())?;
        ThreadId::new(row.get::<_, String>(1)?).map_err(|_error| invalid())?;
        for index in 2..5 {
            let _: String = row.get(index)?;
        }
        let _: i64 = row.get(5)?;
        let _: i64 = row.get(6)?;
    }
    reject_if(
        connection,
        "SELECT count(*) > 1 FROM (SELECT account_id FROM account_identity LIMIT 2)",
    )?;
    let mut identity = connection.prepare(
        "SELECT CASE WHEN typeof(account_id) = 'text' AND length(CAST(account_id AS BLOB)) BETWEEN 1 AND 256 THEN account_id END,
         CASE WHEN typeof(identity_hash) = 'blob' AND length(identity_hash) = 32 THEN identity_hash END,
         CASE WHEN typeof(algo_version) = 'integer' AND algo_version = 2 THEN algo_version END FROM account_identity")?;
    let mut rows = identity.query([])?;
    if let Some(row) = rows.next()? {
        if row.get::<_, String>(0)? != account.as_str() {
            return Err(invalid());
        }
        let _: Vec<u8> = row.get(1)?;
        let _: i64 = row.get(2)?;
    }
    reject_if(
        connection,
        "SELECT count(*) > 1 FROM (SELECT singleton FROM account_lifecycle LIMIT 2)",
    )?;
    reject_if(
        connection,
        "SELECT EXISTS(SELECT 1 FROM account_lifecycle WHERE typeof(singleton) != 'integer' OR singleton != 1 OR (disconnect_recovery IS NOT NULL AND (typeof(disconnect_recovery) != 'integer' OR disconnect_recovery NOT IN (1,2))) OR (last_successful_sync_unix_millis IS NOT NULL AND (typeof(last_successful_sync_unix_millis) != 'integer' OR last_successful_sync_unix_millis < 0)))",
    )?;
    if version >= 2 {
        let address: Option<String> = connection.query_row("SELECT CASE WHEN typeof(email_address) = 'text' AND length(CAST(email_address AS BLOB)) BETWEEN 3 AND 320 THEN email_address END FROM account_binding WHERE singleton = 1",[],|r| r.get(0))?;
        if let Some(address) = address {
            tersa_application::mailbox::AccountEmail::new(address).map_err(|_error| invalid())?;
        }
    }
    Ok(())
}
