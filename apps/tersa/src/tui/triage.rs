// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Keyboard triage. Typed captured values route actions; documents only describe them.
//!
//! Batch selection is limited to 1,000 total keys and clears on search, scope,
//! filter or cache reload. A modal freezes its target snapshot and view epoch.
//! No modal consumes late results or derives eligibility from rendered text.

mod documents;
mod draw;
#[cfg(test)]
mod tests;

use super::{
    MailSource, MessageKey, ViewScope,
    app::{App, Request},
    control::{ControlEvent, ControlJob},
    worker::Workers,
};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};
use tersa_application::{
    AccountCapability,
    command::{
        AbandonConfirmation, CommandSnapshot, CommandStamp, DuplicateRiskConfirmation,
        MailboxCommandKind, MailboxCommandStatus, MessageAction, MessageTargets,
    },
    command_coordinator::CommandWritePolicy,
    mailbox::AccountId,
    mailbox_state::{LabelDefinition, LabelName},
};
use tersa_presentation::{terminal::SafeText, triage as p8};
use tersa_sync_runtime::{CachedMailboxFilter, CommandIntent};

pub(super) use draw::draw;
const MAX_SELECTION: usize = 1_000;
const MAX_NOTICES: usize = 32;
const MIN_MODAL_WIDTH: u16 = 32;
const MIN_MODAL_HEIGHT: u16 = 8;

/// Available from list and message screens without replacing scrolling keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tool {
    Actions,
    Filters,
    Queue,
    Labels,
    Account,
    Inspect,
    Select,
    SelectVisible,
    ClearSelection,
}

#[derive(Debug, Default)]
pub struct Ui {
    pub modal: Option<Modal>,
    pub batch: Vec<MessageKey>,
    pub deferred_reload: bool,
    filter_request: Option<CachedMailboxFilter>,
    notices: VecDeque<(AccountId, SafeText)>,
}
impl Ui {
    /// A resize event invalidates the old frame before the next terminal draw.
    pub fn invalidate_modal_viewport(&mut self) {
        if let Some(modal) = &mut self.modal {
            modal.rendered_size = None;
        }
    }

    pub fn clear_selection(&mut self) {
        self.batch.clear();
    }
    pub fn record(&mut self, account: AccountId, notice: SafeText) {
        if self.notices.len() == MAX_NOTICES {
            self.notices.pop_front();
        }
        self.notices.push_back((account, notice));
    }
}
#[derive(Debug)]
pub struct Modal {
    epoch: u64,
    title: SafeText,
    lines: Vec<SafeText>,
    choices: Vec<Choice>,
    selected: usize,
    scroll: usize,
    follow_selection: bool,
    input: Option<NameInput>,
    /// Set only by the actual modal renderer; a new modal has not been shown yet.
    rendered_size: Option<(u16, u16)>,
}
impl Modal {
    fn has_supported_frame(&self) -> bool {
        self.rendered_size
            .is_some_and(|(width, height)| width >= MIN_MODAL_WIDTH && height >= MIN_MODAL_HEIGHT)
    }
}
#[derive(Clone, Debug)]
struct Choice {
    text: SafeText,
    action: Action,
}
impl Choice {
    fn new(text: &str, action: Action) -> Self {
        Self {
            text: SafeText::single_line(text),
            action,
        }
    }
}
#[derive(Clone, Debug)]
enum Action {
    Close,
    Account(AccountId, Tool),
    Message(MessageAction, Arc<[MessageKey]>),
    ChooseLabel(LabelUse, AccountId, Arc<[MessageKey]>),
    UserLabels(LabelUse, Arc<[MessageKey]>),
    Label(LabelUse, LabelDefinition, Arc<[MessageKey]>),
    Filter(CachedMailboxFilter),
    Command(CommandSnapshot),
    Submit(AccountId, ControlJob),
    Undo(AccountId, CommandStamp),
    Retry(CommandSnapshot),
    Abandon(CommandSnapshot),
    Name(AccountId, Option<LabelDefinition>),
    DeleteLabel(LabelDefinition),
    SubmitLabelDelete(LabelDefinition),
}
#[derive(Clone, Copy, Debug)]
enum LabelUse {
    Manage,
    Filter,
    Apply,
    Remove,
}
struct NameInput {
    account: AccountId,
    label: Option<LabelDefinition>,
    raw: String,
}
impl std::fmt::Debug for NameInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NameInput([REDACTED])")
    }
}
fn show(app: &mut App, title: &str, lines: Vec<SafeText>, choices: Vec<Choice>) {
    app.triage.modal = Some(Modal {
        epoch: app.view_epoch,
        title: SafeText::single_line(title),
        lines,
        choices,
        selected: 0,
        scroll: 0,
        follow_selection: false,
        input: None,
        rendered_size: None,
    });
    app.repaint = true;
}
fn notice(app: &mut App, text: &str) {
    show(
        app,
        "Triage",
        vec![SafeText::single_line(text)],
        vec![Choice::new("Close", Action::Close)],
    );
}
fn owner(app: &App, account: &AccountId) -> String {
    format!(
        "{} [{}]",
        SafeText::single_line(app.account_label(account)),
        p8::render_identifier(account.as_str())
    )
}
fn current_key(app: &App) -> Option<MessageKey> {
    app.open_key()
        .cloned()
        .or_else(|| app.shown_row(app.selected).map(super::Row::message_key))
}
fn targets(app: &App) -> Arc<[MessageKey]> {
    if app.triage.batch.is_empty() {
        current_key(app).into_iter().collect::<Vec<_>>().into()
    } else {
        app.triage.batch.clone().into()
    }
}

/// Only this entrypoint handles triage keys in the production event loop.
/// A returned request changes the query, never a stored command.
pub(super) fn key(
    app: &mut App,
    source: &dyn MailSource,
    workers: &mut Workers,
    key: KeyEvent,
) -> Option<Request> {
    let mut modal = app.triage.modal.take()?;
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.quit = true;
        return None;
    }
    if key.code == KeyCode::Esc {
        return None;
    }
    if modal.epoch != app.view_epoch {
        app.status = Some("The view changed; reopen the action. Nothing was submitted.".to_owned());
        return None;
    }
    if !modal.has_supported_frame() {
        app.triage.modal = Some(modal);
        return None;
    }
    if let Some(input) = &mut modal.input {
        match key.code {
            KeyCode::Enter => return submit_name(app, source, workers, input),
            KeyCode::Backspace => {
                input.raw.pop();
            }
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                if input.raw.len() + c.len_utf8() <= LabelName::MAX_LEN {
                    input.raw.push(c);
                } else {
                    app.status = Some(
                        "Label name limit: 1,024 UTF-8 bytes; input was not added.".to_owned(),
                    );
                }
            }
            _ => {}
        }
    } else {
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => {
                modal.selected = (modal.selected + 1).min(modal.choices.len().saturating_sub(1));
            }
            KeyCode::Up | KeyCode::Char('k') => modal.selected = modal.selected.saturating_sub(1),
            KeyCode::PageDown | KeyCode::Char(' ') => {
                modal.scroll = modal.scroll.saturating_add(app.page);
            }
            KeyCode::PageUp => modal.scroll = modal.scroll.saturating_sub(app.page),
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                modal.scroll = modal.scroll.saturating_sub((app.page / 2).max(1));
            }
            KeyCode::Enter => {
                if let Some(choice) = modal.choices.get(modal.selected) {
                    return act(app, source, workers, choice.action.clone());
                }
            }
            _ => {}
        }
        if matches!(
            key.code,
            KeyCode::Down | KeyCode::Up | KeyCode::Char('j' | 'k')
        ) {
            modal.follow_selection = true;
        }
    }
    app.triage.modal = Some(modal);
    None
}

/// Exact paste bytes are retained independently of their sanitized single-line preview.
pub(super) fn paste(app: &mut App, text: &str) {
    let Some(modal) = app.triage.modal.as_mut() else {
        return;
    };
    if modal.epoch != app.view_epoch || !modal.has_supported_frame() {
        return;
    }
    let Some(input) = modal.input.as_mut() else {
        return;
    };
    if input.raw.len().saturating_add(text.len()) <= LabelName::MAX_LEN {
        input.raw.push_str(text);
    } else {
        app.status = Some("Paste exceeds 1,024 UTF-8 bytes; nothing was pasted.".to_owned());
    }
}

pub(super) fn open(app: &mut App, source: &dyn MailSource, workers: &mut Workers, tool: Tool) {
    match tool {
        Tool::Actions => actions(app),
        Tool::Filters => filters(app),
        Tool::Queue | Tool::Labels | Tool::Account => choose_account(app, tool),
        Tool::Inspect => inspect(app),
        Tool::Select => toggle_selection(app),
        Tool::SelectVisible => select_visible(app),
        Tool::ClearSelection => {
            app.triage.clear_selection();
            app.status = Some("Batch selection cleared.".to_owned());
        }
    }
    // Single-account views have an exact owner; All always asks explicitly.
    if matches!(tool, Tool::Queue | Tool::Labels | Tool::Account)
        && let ViewScope::Account(account) = &app.scope
    {
        let account = account.clone();
        let _ = act(app, source, workers, Action::Account(account, tool));
    }
}
fn choose_account(app: &mut App, tool: Tool) {
    let choices = app
        .accounts
        .iter()
        .map(|(account, _)| {
            Choice::new(&owner(app, account), Action::Account(account.clone(), tool))
        })
        .collect();
    show(
        app,
        "Choose exact account",
        vec![SafeText::single_line(
            "All scope: this operation affects only the account you choose.",
        )],
        choices,
    );
}
fn toggle_selection(app: &mut App) {
    let Some(key) = current_key(app) else {
        return;
    };
    if let Some(i) = app.triage.batch.iter().position(|k| k == &key) {
        app.triage.batch.remove(i);
    } else if app.triage.batch.len() < MAX_SELECTION {
        app.triage.batch.push(key);
    } else {
        app.status = Some(
            "Batch limit is 1,000 total targets. Nothing was added; narrow the selection."
                .to_owned(),
        );
        return;
    }
    app.status = Some(format!(
        "{} selected. Search/view/reload clears selection; m opens explicit actions.",
        app.triage.batch.len()
    ));
}
fn select_visible(app: &mut App) {
    if app.shown.len() > MAX_SELECTION {
        app.status = Some("More than 1,000 shown targets: selection unchanged. Narrow the search or select individually.".to_owned());
        return;
    }
    app.triage.batch = app
        .shown
        .iter()
        .filter_map(|&i| app.rows.get(i).map(super::Row::message_key))
        .collect();
    app.status = Some(format!(
        "{} shown targets selected; selection clears on search/view/reload.",
        app.triage.batch.len()
    ));
}
fn actions(app: &mut App) {
    let targets = targets(app);
    if targets.is_empty() {
        notice(app, "Select a cached message first.");
        return;
    }
    let lines = target_context(app, &targets);
    let mut choices: Vec<_> = [
        ("Read", MessageAction::Read),
        ("Unread", MessageAction::Unread),
        ("Star", MessageAction::Star),
        ("Unstar", MessageAction::Unstar),
        ("Archive", MessageAction::Archive),
        ("Trash", MessageAction::Trash),
        ("Restore to Inbox", MessageAction::Restore),
        ("Spam", MessageAction::Spam),
        ("Clear Spam to Inbox", MessageAction::ClearSpam),
    ]
    .into_iter()
    .map(|(text, action)| Choice::new(text, Action::Message(action, Arc::clone(&targets))))
    .collect();
    choices.push(Choice::new(
        "Apply exact User label…",
        Action::UserLabels(LabelUse::Apply, Arc::clone(&targets)),
    ));
    choices.push(Choice::new(
        "Remove exact User label…",
        Action::UserLabels(LabelUse::Remove, targets),
    ));
    show(app, "Explicit desired action", lines, choices);
}
fn target_context(app: &App, targets: &[MessageKey]) -> Vec<SafeText> {
    let mut counts = BTreeMap::new();
    for (account, _) in targets {
        *counts.entry(account.as_str()).or_insert(0_usize) += 1;
    }
    let mut lines = vec![SafeText::single_line(
        "Observed metadata may be Unknown. Actions set explicit desired state; they never toggle a guessed observation.",
    )];
    for (id, count) in counts {
        let account = targets
            .iter()
            .find(|(a, _)| a.as_str() == id)
            .map(|(a, _)| a)
            .expect("counted owner");
        lines.push(SafeText::single_line(&format!(
            "{}: {count} captured targets",
            owner(app, account)
        )));
    }
    lines
}
fn filters(app: &mut App) {
    let mut choices: Vec<_> = [
        (
            "Recent (all cached; includes Unknown)",
            CachedMailboxFilter::Recent,
        ),
        ("Observed Inbox", CachedMailboxFilter::Inbox),
        ("Observed Trash", CachedMailboxFilter::Trash),
        ("Observed Spam", CachedMailboxFilter::Spam),
    ]
    .into_iter()
    .map(|(text, filter)| Choice::new(text, Action::Filter(filter)))
    .collect();
    for (account, _) in &app.accounts {
        if app.scope.contains(account) {
            choices.push(Choice::new(
                &format!("User label in {}…", owner(app, account)),
                Action::ChooseLabel(LabelUse::Filter, account.clone(), Arc::from([])),
            ));
        }
    }
    show(
        app,
        "Observed mailbox filter",
        vec![SafeText::single_line(
            "Filters use observed memberships before every query page limit. Pending desired state never changes membership. Unknown remains in Recent.",
        )],
        choices,
    );
}
fn inspect(app: &mut App) {
    let Some(key) = current_key(app) else {
        notice(app, "No message selected.");
        return;
    };
    let Some(row) = app.rows.iter().find(|r| r.message_key() == key) else {
        return;
    };
    let mut lines = vec![
        SafeText::single_line(&owner(app, &key.0)),
        p8::render_identifier(key.1.as_str()),
    ];
    if let Some(doc) = &row.triage {
        lines.extend([
            doc.metadata.clone(),
            doc.read.clone(),
            doc.star.clone(),
            doc.folders.clone(),
            doc.label_state.clone(),
        ]);
        for label in &doc.labels {
            lines.push(SafeText::single_line(&format!(
                "Observed label: {} [{}]",
                label.name, label.identifier
            )));
        }
        for pending in &doc.pending {
            lines.push(SafeText::single_line(&format!(
                "Pending desired projection: {}",
                pending.status
            )));
            lines.extend(pending.changes.clone());
        }
        if doc.omitted_labels > 0 || doc.omitted_pending > 0 {
            lines.push(SafeText::single_line("Some document entries omitted; use Labels/Queue for full cached catalogs and pending commands."));
        }
    } else {
        lines.push(SafeText::single_line(
            "Provider metadata unknown; legacy display is not a complete observation.",
        ));
    }
    show(
        app,
        "Current observed state / separate pending intent",
        lines,
        vec![Choice::new("Close", Action::Close)],
    );
}

fn act(
    app: &mut App,
    source: &dyn MailSource,
    workers: &mut Workers,
    action: Action,
) -> Option<Request> {
    match action {
        Action::Close => {}
        Action::Filter(filter) => return Some(Request::ChangeFilter(filter)),
        Action::Message(action, targets) => {
            submit_messages(app, source, workers, &targets, &action);
        }
        Action::UserLabels(purpose, targets) => choose_label_owner(app, purpose, &targets),
        Action::Account(account, tool) => match tool {
            Tool::Queue => queue(app, source, &account),
            Tool::Labels => labels(app, source, LabelUse::Manage, &account, &Arc::from([])),
            _ => account_menu(app, source, &account),
        },
        Action::ChooseLabel(purpose, account, targets) => {
            labels(app, source, purpose, &account, &targets);
        }
        Action::Label(purpose, definition, targets) => {
            label_action(app, source, workers, purpose, definition, &targets);
        }
        Action::Command(snapshot) => command_menu(app, &snapshot),
        Action::Submit(account, job) => submit(app, workers, &account, job),
        Action::Undo(account, expected_source) => confirm(
            app,
            p8::ActionWarning::ConditionalOfflineUndo,
            vec![
                SafeText::single_line(&owner(app, &account)),
                p8::render_identifier(expected_source.key().command_id().as_str()),
            ],
            Action::Submit(
                account,
                ControlJob::Undo {
                    expected_source,
                    resume: true,
                },
            ),
        ),
        Action::Retry(snapshot) => retry(app, &snapshot),
        Action::Abandon(snapshot) => {
            let account = snapshot.stamp().key().account_id().clone();
            confirm(
                app,
                p8::ActionWarning::Abandon,
                documents::command_lines(&snapshot),
                Action::Submit(
                    account,
                    ControlJob::Abandon {
                        stamp: snapshot.stamp().clone(),
                        confirmation: AbandonConfirmation::ProviderMayAlreadyHaveApplied,
                    },
                ),
            );
        }
        Action::Name(account, label) => name_input(app, account, label),
        Action::DeleteLabel(definition) => {
            let text = documents::label_input(&definition);
            confirm(
                app,
                p8::ActionWarning::DeleteLabel(text),
                vec![SafeText::single_line(&owner(app, definition.account_id()))],
                Action::SubmitLabelDelete(definition.clone()),
            );
        }
        Action::SubmitLabelDelete(definition) => {
            if !may_modify(app, source, definition.account_id()) {
                return None;
            }
            if label_unchanged(source, &definition) {
                let account = definition.account_id().clone();
                match definition.user_label() {
                    Ok(label) => submit(
                        app,
                        workers,
                        &account,
                        ControlJob::Admit {
                            intent: CommandIntent::DeleteLabel(label),
                            resume: true,
                        },
                    ),
                    Err(_error) => notice(app, "Only known User labels may be deleted."),
                }
            } else {
                notice(
                    app,
                    "The cached label changed or is unavailable. Reopen Labels; nothing was submitted.",
                );
            }
        }
    }
    app.triage.filter_request.take().map(Request::ChangeFilter)
}
fn confirm(
    app: &mut App,
    warning: p8::ActionWarning<'_>,
    mut context: Vec<SafeText>,
    action: Action,
) {
    let doc = p8::render_warning(warning);
    context.push(doc.explanation);
    if let Some(label) = doc.label {
        context.push(SafeText::single_line(&format!(
            "{} [{}]",
            label.name, label.identifier
        )));
    }
    show(
        app,
        doc.title.as_str(),
        context,
        vec![
            Choice::new("Cancel (default)", Action::Close),
            Choice::new("Confirm this exact captured action", action),
        ],
    );
}
fn submit(app: &mut App, workers: &mut Workers, account: &AccountId, job: ControlJob) {
    let queued = workers
        .accounts
        .iter_mut()
        .find(|w| &w.account == account)
        .and_then(|w| w.control(job, app.view_epoch))
        .is_some();
    let text = if queued {
        "Submitted in memory; durable admission is not yet confirmed. Q shows account receipts and online outcomes."
    } else {
        "Not submitted: account worker unavailable or four outstanding controls reached. No durable admission was claimed."
    };
    let notice = SafeText::single_line(&format!("{}: {text}", owner(app, account)));
    app.status = Some(notice.to_string());
    app.triage.record(account.clone(), notice);
}
fn submit_messages(
    app: &mut App,
    source: &dyn MailSource,
    workers: &mut Workers,
    targets: &[MessageKey],
    action: &MessageAction,
) {
    let mut groups: BTreeMap<&str, (AccountId, Vec<tersa_application::mailbox::MessageId>)> =
        BTreeMap::new();
    for (account, id) in targets {
        groups
            .entry(account.as_str())
            .or_insert_with(|| (account.clone(), Vec::new()))
            .1
            .push(id.clone());
    }
    let mut notices = Vec::new();
    for (account, ids) in groups.values() {
        let error = match source.account_state(account) {
            Ok(state) if state.metadata.capability() == AccountCapability::Modify => None,
            Ok(_) => Some("ReadOnly: no command admitted. Use A → Upgrade for this account."),
            Err(()) => Some("Account state unavailable; no command submitted."),
        };
        let wrong_label_owner = match action {
            MessageAction::ApplyLabel(label) | MessageAction::RemoveLabel(label) => {
                label.account_id() != account
            }
            _ => false,
        };
        if let Some(error) = error.or(wrong_label_owner
            .then_some("User label belongs to another account; this group was not submitted."))
        {
            let text = SafeText::single_line(&format!(
                "{} ({} targets): {error}",
                owner(app, account),
                ids.len()
            ));
            app.triage.record(account.clone(), text.clone());
            notices.push(text);
            continue;
        }
        match MessageTargets::new(account.clone(), ids.clone()) {
            Ok(targets) => {
                submit(
                    app,
                    workers,
                    account,
                    ControlJob::Admit {
                        intent: CommandIntent::Messages {
                            targets,
                            action: action.clone(),
                        },
                        resume: true,
                    },
                );
                if let Some(text) = &app.status {
                    notices.push(SafeText::single_line(text));
                }
            }
            Err(_error) => notices.push(SafeText::single_line(
                "Invalid or oversized exact target group; nothing submitted for that group.",
            )),
        }
    }
    app.triage.clear_selection();
    show(
        app,
        "Independent account submissions",
        notices,
        vec![Choice::new("Close; Q shows durable results", Action::Close)],
    );
}
fn account_menu(app: &mut App, source: &dyn MailSource, account: &AccountId) {
    let Ok(state) = source.account_state(account) else {
        notice(
            app,
            "Account unavailable; no authority or recovery state is assumed.",
        );
        return;
    };
    let mut choices = vec![
        Choice::new(
            "Reload account status",
            Action::Submit(account.clone(), ControlJob::Status),
        ),
        Choice::new(
            "Observe/recover once (read access; no write)",
            Action::Submit(account.clone(), ControlJob::Drive(None)),
        ),
        Choice::new(
            "Drive once (automatic budget; leaves explicit retry tickets untouched)",
            Action::Submit(
                account.clone(),
                ControlJob::Drive(Some(CommandWritePolicy::Automatic)),
            ),
        ),
        Choice::new(
            "Upgrade this account to Modify…",
            Action::Submit(account.clone(), ControlJob::Upgrade),
        ),
        Choice::new(
            "Reconnect this account (preserve stored capability)…",
            Action::Submit(account.clone(), ControlJob::Reconnect),
        ),
    ];
    if let Some(candidate) = &state.undo {
        choices.push(Choice::new(
            "Conditional Undo of last Complete message command…",
            Action::Undo(account.clone(), candidate.source().clone()),
        ));
    }
    let mut lines = documents::account_lines(&state);
    lines.push(SafeText::single_line("Browser consent is account-bound. Closing Tersa cancels owned account work; the external browser application may remain open."));
    show(
        app,
        &format!("Account: {}", owner(app, account)),
        lines,
        choices,
    );
}
fn queue(app: &mut App, source: &dyn MailSource, account: &AccountId) {
    let Ok(state) = source.account_state(account) else {
        notice(app, "Queue unavailable; no command state was changed.");
        return;
    };
    let mut lines = documents::account_lines(&state);
    lines.push(SafeText::single_line("Pending desired intent is separate from current observed provider state. Terminal results do not establish cache convergence."));
    let mut choices = Vec::new();
    for snapshot in state.pending {
        choices.push(Choice::new(
            &documents::command_heading(&snapshot),
            Action::Command(snapshot),
        ));
    }
    for summary in state.terminal.summaries() {
        lines.extend(documents::terminal_lines(summary));
    }
    for (owner, notice) in &app.triage.notices {
        if owner == account {
            lines.push(notice.clone());
        }
    }
    if let Some(candidate) = state.undo {
        choices.push(Choice::new(
            "Conditional Undo of last Complete message command…",
            Action::Undo(account.clone(), candidate.source().clone()),
        ));
    }
    choices.push(Choice::new(
        "Reload status (reopen Q after completion)",
        Action::Submit(account.clone(), ControlJob::Status),
    ));
    choices.push(Choice::new(
        "Observe/recover one pass; no write",
        Action::Submit(account.clone(), ControlJob::Drive(None)),
    ));
    show(
        app,
        &format!("Queue: {}", owner(app, account)),
        lines,
        choices,
    );
}
fn command_menu(app: &mut App, snapshot: &CommandSnapshot) {
    let account = snapshot.stamp().key().account_id().clone();
    let mut choices = vec![Choice::new("Close", Action::Close)];
    match snapshot.status() {
        MailboxCommandStatus::Queued => choices.push(Choice::new(
            "Cancel still-Queued local intent",
            Action::Submit(
                account.clone(),
                ControlJob::Cancel(snapshot.stamp().clone()),
            ),
        )),
        MailboxCommandStatus::Ambiguous | MailboxCommandStatus::NeedsAttention => {
            choices.push(Choice::new(
                "Explicit Retry of this command…",
                Action::Retry(snapshot.clone()),
            ));
        }
        _ => {}
    }
    if !snapshot.status().is_terminal() {
        choices.push(Choice::new(
            "Warned Abandon of this command…",
            Action::Abandon(snapshot.clone()),
        ));
        choices.push(Choice::new(
            "Fresh observation/recovery pass; no write",
            Action::Submit(account, ControlJob::Drive(None)),
        ));
    }
    show(
        app,
        "Exact command",
        documents::command_lines(snapshot),
        choices,
    );
}
fn retry(app: &mut App, snapshot: &CommandSnapshot) {
    let stamp = snapshot.stamp().clone();
    let account = stamp.key().account_id().clone();
    let create = matches!(
        snapshot.command().kind(),
        MailboxCommandKind::CreateLabel(_)
    );
    let policy = CommandWritePolicy::ExplicitRetry {
        key: stamp.key().clone(),
        duplicate_risk: if create {
            DuplicateRiskConfirmation::Confirmed
        } else {
            DuplicateRiskConfirmation::NotConfirmed
        },
    };
    let job = ControlJob::AuthorizeRetry {
        stamp,
        resume: Some(policy),
    };
    if create {
        confirm(
            app,
            p8::ActionWarning::RetryPossibleLabelCreate,
            documents::command_lines(snapshot),
            Action::Submit(account, job),
        );
    } else {
        // Explicitly selecting Retry is consent for reversible message/known-ID work.
        // The coordinator still performs fresh observations and at most one dispatch.
        show(
            app,
            "Explicit Retry",
            documents::command_lines(snapshot),
            vec![
                Choice::new("Cancel (default)", Action::Close),
                Choice::new(
                    "Retry this exact command once",
                    Action::Submit(account, job),
                ),
            ],
        );
    }
}
fn labels(
    app: &mut App,
    source: &dyn MailSource,
    purpose: LabelUse,
    account: &AccountId,
    targets: &Arc<[MessageKey]>,
) {
    let mut choices = vec![Choice::new(
        "Refresh complete catalog online (reopen L/F/m after completion)",
        Action::Submit(account.clone(), ControlJob::Catalog { refresh: true }),
    )];
    if matches!(purpose, LabelUse::Manage) {
        choices.push(Choice::new(
            "Create exact User-label name…",
            Action::Name(account.clone(), None),
        ));
    }
    let mut lines = vec![SafeText::single_line(&owner(app, account))];
    match source.label_catalog(account) {
        Ok(Some(catalog)) => {
            lines.push(SafeText::single_line(&format!("Complete cached catalog: {} definitions. Cached observations may be stale; dispatch verifies current label identity/kind.", catalog.definitions().len())));
            for definition in catalog.definitions() {
                let doc = p8::render_label(documents::label_input(definition));
                if definition.user_label().is_ok() {
                    choices.push(Choice::new(&format!("{} [{}]", doc.name, doc.identifier), Action::Label(purpose, definition.clone(), Arc::clone(targets))));
                } else { lines.push(SafeText::single_line(&format!("System (read only): {} [{}]", doc.name, doc.identifier))); }
            }
        }
        Ok(None) => lines.push(SafeText::single_line("Catalog unknown; no User-label identity or empty catalog is assumed. Refresh when online.")),
        Err(()) => lines.push(SafeText::single_line("Catalog unavailable. No label actions were inferred.")),
    }
    if !targets.is_empty() {
        lines.extend(target_context(app, targets));
    }
    show(app, "Account-bound User labels", lines, choices);
}
fn label_action(
    app: &mut App,
    source: &dyn MailSource,
    workers: &mut Workers,
    purpose: LabelUse,
    definition: LabelDefinition,
    targets: &Arc<[MessageKey]>,
) {
    if !label_unchanged(source, &definition) {
        notice(
            app,
            "Label catalog changed or is unavailable; reopen the label choice. Nothing was submitted.",
        );
        return;
    }
    let Ok(label) = definition.user_label() else {
        notice(app, "System labels cannot be modified.");
        return;
    };
    match purpose {
        LabelUse::Filter => {
            app.triage.modal = None;
            app.triage.filter_request = Some(CachedMailboxFilter::UserLabel(label));
        }
        LabelUse::Apply => submit_messages(
            app,
            source,
            workers,
            targets,
            &MessageAction::ApplyLabel(label),
        ),
        LabelUse::Remove => submit_messages(
            app,
            source,
            workers,
            targets,
            &MessageAction::RemoveLabel(label),
        ),
        LabelUse::Manage => {
            let doc = p8::render_label(documents::label_input(&definition));
            show(
                app,
                "Exact User-label definition",
                vec![doc.name, doc.identifier],
                vec![
                    Choice::new(
                        "Rename this exact User-label ID…",
                        Action::Name(definition.account_id().clone(), Some(definition.clone())),
                    ),
                    Choice::new(
                        "Delete definition and assignments…",
                        Action::DeleteLabel(definition),
                    ),
                ],
            );
        }
    }
}
fn label_unchanged(source: &dyn MailSource, definition: &LabelDefinition) -> bool {
    source
        .label_catalog(definition.account_id())
        .ok()
        .flatten()
        .is_some_and(|catalog| catalog.definitions().contains(definition))
}
fn name_input(app: &mut App, account: AccountId, label: Option<LabelDefinition>) {
    let mut lines = vec![
        SafeText::single_line(&owner(app, &account)),
        SafeText::single_line(
            "Exact UTF-8 name, 1–1,024 bytes. Paste retains raw bytes; preview is sanitized. Enter submits; Esc cancels.",
        ),
    ];
    if let Some(definition) = &label {
        let doc = p8::render_label(documents::label_input(definition));
        lines.push(SafeText::single_line(&format!(
            "Rename {} [{}]",
            doc.name, doc.identifier
        )));
    }
    show(app, "User-label name", lines, Vec::new());
    if let Some(modal) = &mut app.triage.modal {
        modal.input = Some(NameInput {
            account,
            label,
            raw: String::new(),
        });
    }
}
fn submit_name(
    app: &mut App,
    source: &dyn MailSource,
    workers: &mut Workers,
    input: &NameInput,
) -> Option<Request> {
    let Ok(name) = LabelName::new(input.raw.clone()) else {
        notice(
            app,
            "Name must contain 1–1,024 UTF-8 bytes. Nothing was submitted; reopen the input.",
        );
        return None;
    };
    let intent = if let Some(definition) = &input.label {
        if !label_unchanged(source, definition) {
            notice(
                app,
                "The label changed while editing. Nothing was submitted; reopen Labels.",
            );
            return None;
        }
        let Ok(label) = definition.user_label() else {
            return None;
        };
        CommandIntent::RenameLabel { label, name }
    } else {
        CommandIntent::CreateLabel(name)
    };
    match source.account_state(&input.account) {
        Ok(state) if state.metadata.capability() == AccountCapability::Modify => submit(
            app,
            workers,
            &input.account,
            ControlJob::Admit {
                intent,
                resume: true,
            },
        ),
        Ok(_) => notice(
            app,
            "ReadOnly: no label command admitted. Use A → Upgrade for this account.",
        ),
        Err(()) => notice(app, "Account unavailable; no label command submitted."),
    }
    None
}

/// Retain bounded owner outcomes separately from the frozen current dialog.
pub(super) fn completed(app: &mut App, event: &ControlEvent) {
    let account = event.binding().account.clone();
    let text = match event {
        ControlEvent::Progress(_, super::control::Progress::Durable(receipt)) => receipt.notice(),
        ControlEvent::Progress(_, super::control::Progress::AuthorizationLink(link)) => {
            // This is the bounded fallback URL, never token material. Keep it
            // available in Q even if consent or another request finishes later.
            SafeText::single_line(&format!("Authorization link: {link}"))
        }
        ControlEvent::Finished(_, Ok(result)) => result.notice(),
        ControlEvent::Finished(_, Err(error)) => SafeText::single_line(&format!(
            "Request ended with an error: {error}. Any earlier durable receipt remains saved. Reload status before choosing another action."
        )),
    };
    app.triage.record(account, text);
}

fn choose_label_owner(app: &mut App, purpose: LabelUse, targets: &Arc<[MessageKey]>) {
    let mut choices = Vec::new();
    for (account, _) in &app.accounts {
        let count = targets.iter().filter(|(a, _)| a == account).count();
        if count > 0 {
            choices.push(Choice::new(
                &format!(
                    "{}: {count} owned targets; {} targets in other accounts will fail",
                    owner(app, account),
                    targets.len() - count
                ),
                Action::ChooseLabel(purpose, account.clone(), Arc::clone(targets)),
            ));
        }
    }
    show(
        app,
        "Choose label owner",
        target_context(app, targets),
        choices,
    );
}
impl Tool {
    pub fn from_key(code: KeyCode) -> Option<Self> {
        match code {
            KeyCode::Char('m') => Some(Self::Actions),
            KeyCode::Char('F') => Some(Self::Filters),
            KeyCode::Char('Q') => Some(Self::Queue),
            KeyCode::Char('L') => Some(Self::Labels),
            KeyCode::Char('A') => Some(Self::Account),
            KeyCode::Char('i') => Some(Self::Inspect),
            KeyCode::Char('v') => Some(Self::Select),
            KeyCode::Char('V') => Some(Self::SelectVisible),
            KeyCode::Char('X') => Some(Self::ClearSelection),
            _ => None,
        }
    }
}

fn may_modify(app: &mut App, source: &dyn MailSource, account: &AccountId) -> bool {
    match source.account_state(account) {
        Ok(state) if state.metadata.capability() == AccountCapability::Modify => true,
        Ok(_) => {
            notice(
                app,
                "ReadOnly: no command admitted. Use A → Upgrade for this account.",
            );
            false
        }
        Err(()) => {
            notice(app, "Account state unavailable; nothing was submitted.");
            false
        }
    }
}
