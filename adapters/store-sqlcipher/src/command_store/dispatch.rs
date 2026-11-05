// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Persists possible-dispatch markers and derives settlement from full observations.

use super::{advance, authority, current, finish, save, write};
use crate::{SqlCipherMailboxStore, command_codec::Body};
use tersa_application::{
    command::{
        CommandEvidence, CommandPrecondition, CommandReconciliation, CommandRejection,
        CommandSnapshot, DispatchAuthorization, DispatchFact, DispatchPreparation, DispatchReceipt,
        DuplicateRiskConfirmation, LabelCreateMatches, MAX_AUTOMATIC_ATTEMPTS,
        RemoteCommandOutcome, WriteAcknowledgement,
    },
    mailbox_state::{RemoteMessageState, TriageStoreError as Error},
};
use tersa_domain::{
    command::{CommandItemOutcome, MailboxCommandStatus, MailboxField, MessageTargets},
    label::ObservedMembership,
    mailbox::AccountId,
};

fn fresh(
    body: &Body,
    account: &AccountId,
    reconciliation: &CommandReconciliation,
) -> Result<(), Error> {
    if &body.snapshot(account)? != reconciliation.snapshot() {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn label_available(evidence: &CommandEvidence) -> bool {
    match evidence {
        CommandEvidence::Messages {
            user_label: Some(label),
            ..
        } => label.definition().is_some(),
        _ => true,
    }
}
fn compensation_matches(body: &Body, evidence: &CommandEvidence) -> bool {
    if body.header.kind != 1 || body.header.guard.is_some() {
        return true;
    }
    let CommandEvidence::Messages { observations, .. } = evidence else {
        return false;
    };
    label_available(evidence)
        && body
            .items
            .iter()
            .zip(observations.observations())
            .all(|(item, observed)| match observed.state() {
                RemoteMessageState::Known(labels) => {
                    item.expected.as_ref().is_some_and(|expected| {
                        expected.is_observed_in(&ObservedMembership::Observed(labels.clone()))
                    })
                }
                RemoteMessageState::Missing => false,
            })
}
fn observe(body: &mut Body, reconciliation: &CommandReconciliation) -> Result<(), Error> {
    let available = label_available(reconciliation.evidence());
    match reconciliation.evidence() {
        CommandEvidence::Messages {
            observations,
            user_label,
        } => {
            body.header.label_observation = user_label
                .as_ref()
                .map(|label| label.definition().is_some());
            body.header.observed_label = user_label
                .as_ref()
                .and_then(|label| label.definition())
                .cloned();
            for (item, observation) in body.items.iter_mut().zip(observations.observations()) {
                // A settled item retains its actual successful observation and original touched pre-state.
                if item.outcome.is_some() {
                    continue;
                }
                item.observation = Some(observation.state().clone());
                match observation.state() {
                    RemoteMessageState::Missing => {
                        item.post = None;
                        item.outcome = Some(CommandItemOutcome::TargetMissing);
                    }
                    RemoteMessageState::Known(labels) => {
                        let observed = ObservedMembership::Observed(labels.clone());
                        let actual = item
                            .desired
                            .record_pre_state(&observed)
                            .ok_or(Error::Corrupt)?;
                        if body.header.dispatch.is_none() || item.pre.is_none() {
                            item.pre = Some(actual.clone());
                        }
                        item.post = Some(actual);
                        // Observed ordinary removal needs no write when the exact ID is already absent,
                        // even if the definition disappeared. Conditional undo still requires its label.
                        let ordinary_removal = body.header.kind == 0
                            && item.desired.memberships().iter().all(|v| {
                                matches!(v.field(), MailboxField::UserLabel(_)) && !v.is_present()
                            });
                        if (available || ordinary_removal) && item.desired.is_observed_in(&observed)
                        {
                            item.outcome = Some(CommandItemOutcome::DesiredStateObserved);
                        } else if !available || (body.header.fact == Some(6) && item.selected) {
                            item.outcome = Some(CommandItemOutcome::Failed);
                        }
                    }
                }
            }
        }
        CommandEvidence::CreateCatalog(_) => {
            body.header.matches = Some(
                match reconciliation.create_matches().ok_or(Error::Corrupt)? {
                    LabelCreateMatches::Zero => {
                        body.header.observed_label = None;
                        if body.header.fact == Some(6) {
                            body.header.label_progress = 2;
                        }
                        0
                    }
                    LabelCreateMatches::One(label) => {
                        let CommandEvidence::CreateCatalog(catalog) = reconciliation.evidence()
                        else {
                            return Err(Error::Corrupt);
                        };
                        body.header.observed_label = catalog
                            .definitions()
                            .iter()
                            .find(|d| d.id() == label.id())
                            .cloned();
                        body.header.label_progress = 1;
                        1
                    }
                    LabelCreateMatches::Multiple => {
                        body.header.observed_label = None;
                        2
                    }
                },
            );
        }
        CommandEvidence::UserLabel(observed) => {
            body.header.label_observation = Some(observed.definition().is_some());
            body.header.observed_label = observed.definition().cloned();
            body.header.label_progress = match (&body.header.name, observed.definition()) {
                (None, None) => 1, // Exact known-ID absence proves delete.
                (Some(name), Some(definition)) if name == definition.name() => 1,
                (Some(_), None) => 2, // Rename cannot resurrect an absent definition.
                _ if body.header.fact == Some(6) => 2,
                _ => 0,
            };
        }
    }
    Ok(())
}
fn settled_status(body: &Body) -> Option<MailboxCommandStatus> {
    if body.header.kind >= 2 {
        return match body.header.label_progress {
            1 => Some(MailboxCommandStatus::Complete),
            2 => Some(MailboxCommandStatus::Partial),
            _ => None,
        };
    }
    if body.items.iter().any(|i| i.outcome.is_none()) {
        return None;
    }
    Some(
        if body
            .items
            .iter()
            .all(|i| i.outcome == Some(CommandItemOutcome::DesiredStateObserved))
        {
            MailboxCommandStatus::Complete
        } else {
            MailboxCommandStatus::Partial
        },
    )
}

#[expect(
    clippy::too_many_lines,
    reason = "The pre-dispatch transaction checks authority, fresh evidence, selection and durable markers together"
)]
pub(super) fn prepare(
    store: &SqlCipherMailboxStore,
    request: &DispatchPreparation,
) -> Result<DispatchReceipt, Error> {
    write(store, request.precondition().fence(), |tx| {
        let mut body = current(tx, request.precondition(), true)?;
        fresh(&body, &store.account, request.reconciliation())?;
        if body.header.status == MailboxCommandStatus::Dispatching {
            return Err(Error::NotEligible);
        }
        authority(tx)?;
        if !compensation_matches(&body, request.reconciliation().evidence())
            || !label_available(request.reconciliation().evidence())
        {
            return Err(Error::NotEligible);
        }
        match request.authorization() {
            DispatchAuthorization::Automatic => {
                if body.header.attempts >= MAX_AUTOMATIC_ATTEMPTS
                    || body.header.retry.is_some()
                    || (body.header.kind == 2 && body.header.dispatch.is_some())
                    || body.header.fact == Some(6)
                {
                    return Err(Error::NotEligible);
                }
            }
            DispatchAuthorization::Explicit(ticket) => {
                if body.header.retry != Some(body.header.revision)
                    || ticket.stamp() != &body.header.stamp(&store.account)
                {
                    return Err(Error::Conflict);
                }
            }
        }
        match request.reconciliation().evidence() {
            CommandEvidence::Messages { observations, .. } => {
                let targets = request.targets().ok_or(Error::NotEligible)?;
                for id in targets.ids() {
                    let item = body
                        .items
                        .iter()
                        .find(|i| &i.id == id && i.outcome.is_none())
                        .ok_or(Error::Conflict)?;
                    let observation = observations
                        .observations()
                        .iter()
                        .find(|o| o.key().message_id() == id)
                        .ok_or(Error::Conflict)?;
                    match observation.state() {
                        RemoteMessageState::Known(labels)
                            if !item
                                .desired
                                .is_observed_in(&ObservedMembership::Observed(labels.clone())) => {}
                        _ => return Err(Error::NotEligible),
                    }
                }
            }
            CommandEvidence::CreateCatalog(_) => {
                if request.targets().is_some()
                    || request.reconciliation().create_matches() != Some(LabelCreateMatches::Zero)
                {
                    return Err(Error::NotEligible);
                }
                if body.header.dispatch.is_some()
                    && (!matches!(request.authorization(), DispatchAuthorization::Explicit(_))
                        || request.duplicate_risk() != DuplicateRiskConfirmation::Confirmed)
                {
                    return Err(Error::NotEligible);
                }
            }
            CommandEvidence::UserLabel(observed) => {
                if request.targets().is_some()
                    || observed.definition().is_none()
                    || (body.header.kind == 3
                        && observed
                            .definition()
                            .map(tersa_domain::label::LabelDefinition::name)
                            == body.header.name.as_ref())
                {
                    return Err(Error::NotEligible);
                }
            }
        }
        // Capture the whole fresh observation, including already-desired targets,
        // before committing any possible dispatch. Only the unmet subset is selected.
        observe(&mut body, request.reconciliation())?;
        for item in &mut body.items {
            item.selected = request
                .targets()
                .is_some_and(|targets| targets.ids().contains(&item.id));
            if item.selected && item.outcome.is_some() {
                return Err(Error::NotEligible);
            }
        }
        advance(&mut body)?;
        body.header.status = MailboxCommandStatus::Dispatching;
        body.header.dispatch = Some(body.header.revision);
        body.header.fact = None;
        body.header.dispatch_label = None;
        body.header.failure = None;
        body.header.authorization = Some(match request.authorization() {
            DispatchAuthorization::Automatic => {
                body.header.attempts += 1;
                0
            }
            DispatchAuthorization::Explicit(_) => 1,
        });
        body.header.retry = None;
        body.header.duplicate_risk = body.header.kind == 2
            && request.duplicate_risk() == DuplicateRiskConfirmation::Confirmed;
        if body.header.kind == 1 && body.header.guard.is_none() {
            body.header.guard = Some(body.header.revision);
        }
        save(tx, &body)?;
        DispatchReceipt::from_committed(body.snapshot(&store.account)?, request.targets().cloned())
            .map_err(|_error| Error::Corrupt)
    })
}
pub(super) fn record(
    store: &SqlCipherMailboxStore,
    expected: &CommandPrecondition,
    outcome: &RemoteCommandOutcome,
) -> Result<CommandSnapshot, Error> {
    write(store, expected.fence(), |tx| {
        let mut body = current(tx, expected, true)?;
        if outcome.stamp() != expected.stamp() || body.header.dispatch != Some(body.header.revision)
        {
            return Err(Error::Conflict);
        }
        if body.header.status != MailboxCommandStatus::Dispatching {
            return Err(Error::NotEligible);
        }
        // Revalidate the fact against actual intent and the durable selected subset.
        let targets = if body.header.kind < 2 {
            Some(
                MessageTargets::new(
                    store.account.clone(),
                    body.items
                        .iter()
                        .filter(|i| i.selected)
                        .map(|i| i.id.clone())
                        .collect(),
                )
                .map_err(|_error| Error::Corrupt)?,
            )
        } else {
            None
        };
        let receipt = DispatchReceipt::from_committed(body.snapshot(&store.account)?, targets)
            .map_err(|_error| Error::Corrupt)?;
        RemoteCommandOutcome::new(&receipt, outcome.fact().clone())
            .map_err(|_error| Error::Conflict)?;
        body.header.fact = Some(match outcome.fact() {
            DispatchFact::Acknowledged(WriteAcknowledgement::MessageBatchAccepted) => 0,
            DispatchFact::Acknowledged(WriteAcknowledgement::LabelCreated(label)) => {
                body.header.dispatch_label = Some(label.clone());
                1
            }
            DispatchFact::Acknowledged(WriteAcknowledgement::LabelDefinitionAccepted) => 2,
            DispatchFact::Ambiguous => 3,
            DispatchFact::Rejected(CommandRejection::AuthorizationRequired) => 4,
            DispatchFact::Rejected(CommandRejection::RateLimited) => 5,
            DispatchFact::Rejected(CommandRejection::Rejected) => 6,
        });
        advance(&mut body)?;
        body.header.status = if matches!(outcome.fact(), DispatchFact::Rejected(_)) {
            MailboxCommandStatus::NeedsAttention
        } else {
            MailboxCommandStatus::Ambiguous
        };
        save(tx, &body)?;
        body.snapshot(&store.account)
    })
}
pub(super) fn reconcile(
    store: &SqlCipherMailboxStore,
    expected: &CommandPrecondition,
    observations: &CommandReconciliation,
) -> Result<CommandSnapshot, Error> {
    write(store, expected.fence(), |tx| {
        let mut body = current(tx, expected, true)?;
        fresh(&body, &store.account, observations)?;
        advance(&mut body)?;
        if !compensation_matches(&body, observations.evidence()) {
            body.header.status = MailboxCommandStatus::NeedsAttention;
            body.header.failure = Some(2);
            body.header.retry = None;
            save(tx, &body)?;
            return body.snapshot(&store.account);
        }
        observe(&mut body, observations)?;
        body.header.failure = None;
        if let Some(status) = settled_status(&body) {
            body.header.status = status;
            body.header.retry = None;
            let snapshot = body.snapshot(&store.account)?;
            finish(tx, &store.account, &body)?;
            return Ok(snapshot);
        }
        body.header.status = if body.header.retry.is_some()
            || body.header.attempts >= MAX_AUTOMATIC_ATTEMPTS
            || body.header.kind == 2 && body.header.dispatch.is_some()
        {
            MailboxCommandStatus::NeedsAttention
        } else if body.header.dispatch.is_some() {
            MailboxCommandStatus::Ambiguous
        } else if body.header.status == MailboxCommandStatus::Queued {
            MailboxCommandStatus::Queued
        } else {
            MailboxCommandStatus::NeedsAttention
        };
        save(tx, &body)?;
        body.snapshot(&store.account)
    })
}
