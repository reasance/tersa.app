// This Source Code Form is subject to the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Offline durable controls and one-pass online command composition.

use crate::{AccountHistoryReport, CompositionError, Runtime, SharedSession};
use tersa_application::{
    AccountCapability,
    command::{
        AbandonConfirmation, CommandAdmission, CommandAdmissionOutcome, CommandDispatchError,
        CommandKey, CommandPrecondition, CommandSnapshot, CommandStamp, DispatchFact,
        DispatchReceipt, MailboxCommand, MailboxCommandId, MessageAction, MessageTargets,
        RemoteCommandOutcome, RemoteMailboxCommands, RetainedCommand, RetryAuthorization,
        TerminalCommandSummary, TerminalSummaries, UndoAdmission, UndoCandidate,
        UserLabelObservation,
    },
    command_coordinator::{
        CommandDriveReport, CommandDriveStop, CommandWritePolicy, MailboxCommandCoordinator,
    },
    lifecycle::{AccountLifecycleMetadata, AccountLifecycleStore},
    mailbox::{AccountId, BoxFuture},
    mailbox_state::{LabelCatalog, LabelName, MetadataReadError, TriageStoreError, UserLabel},
    profile::{AccountFence, AccountMetadata, AccountMetadataReader},
};
use tersa_store_sqlcipher::{SqlCipherMailboxStore, StoreCredential};

/// Closed new user intent; runtime generates its fresh durable command identity.
#[derive(Clone, Debug)]
pub enum CommandIntent {
    /// Applies one approved desired-state action to exact same-account messages.
    Messages {
        targets: MessageTargets,
        action: MessageAction,
    },
    /// Creates one name-only User label.
    CreateLabel(LabelName),
    /// Renames one classified, account-bound User label.
    RenameLabel { label: UserLabel, name: LabelName },
    /// Deletes one classified User-label definition, never messages.
    DeleteLabel(UserLabel),
}
impl CommandIntent {
    fn build(
        &self,
        account: &AccountId,
        capability: AccountCapability,
        id: MailboxCommandId,
    ) -> Result<MailboxCommand, CompositionError> {
        let command = match self {
            Self::Messages { targets, action } => {
                MailboxCommand::message_state(capability, id, targets.clone(), action)?
            }
            Self::CreateLabel(name) => {
                MailboxCommand::create_label(capability, id, account.clone(), name.clone())?
            }
            Self::RenameLabel { label, name } => {
                MailboxCommand::rename_label(capability, id, label.clone(), name.clone())?
            }
            Self::DeleteLabel(label) => {
                MailboxCommand::delete_label(capability, id, label.clone())?
            }
        };
        if command.account_id() != account {
            return Err(TriageStoreError::UnknownAccount.into());
        }
        Ok(command)
    }
}

/// Credential purpose without exposing a credential or subject.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialPurpose {
    /// Explicit reconnect is needed for access; local controls remain possible.
    Missing,
    /// A stored refresh credential exists, without claiming current provider access.
    Active,
    /// A rejected rotation is retained only for revocation.
    RevocationOnly,
}
/// Cached durable account status, without online recovery or dispatch.
#[derive(Debug)]
pub struct AccountCommandStatus {
    /// Existing profile and stored capability.
    pub metadata: AccountMetadata,
    /// Local credential purpose, never a usable-token promise.
    pub credential: CredentialPurpose,
    /// Disconnect recovery and last fully successful sync metadata.
    pub lifecycle: AccountLifecycleMetadata,
    /// Every pending command in FIFO order; Dispatching is preserved.
    pub pending: Vec<CommandSnapshot>,
    /// Bounded retained terminal facts.
    pub terminal: TerminalSummaries,
    /// Conditional undo source, without claiming current eligibility.
    pub undo: Option<UndoCandidate>,
}
/// Cache convergence is separate from confirmed command disposition.
#[derive(Debug)]
pub struct CacheConvergenceReport {
    /// A real bounded History cycle and optional body phase.
    pub history: Result<AccountHistoryReport, CompositionError>,
    /// A real complete catalog read and identity-fenced replacement.
    pub catalog: Result<(), CompositionError>,
}
/// One reconciliation pass and at most one dispatch, never a command-draining loop.
#[derive(Debug)]
pub struct AccountCommandReport {
    /// Coordinator-owned durable progress and transport uncertainty.
    pub command: CommandDriveReport,
    /// Attempted after terminal reconciliation; failure never undoes command completion.
    pub convergence: Option<CacheConvergenceReport>,
}
fn fresh_id() -> Result<MailboxCommandId, CompositionError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_error| CompositionError::Entropy)?;
    let value = crate::installation::hex(&bytes);
    MailboxCommandId::new(value).map_err(CompositionError::Intent)
}
impl Runtime {
    /// Admits a fresh offline intent using only the existing account store.
    ///
    /// # Errors
    /// Rejects wrong account/identity, `ReadOnly` capability, quota or invalid intent.
    pub async fn admit_command(
        &self,
        account: &AccountId,
        intent: &CommandIntent,
    ) -> Result<CommandAdmissionOutcome, CompositionError> {
        let operation = self.operations.get(account)?;
        let _permit = operation.permit.lock().await;
        let (store, fence) = self.local_context(account).await?;
        let metadata = store
            .read_metadata(account)
            .await?
            .ok_or(TriageStoreError::UnknownAccount)?;
        let command = intent.build(account, metadata.capability(), fresh_id()?)?;
        Ok(MailboxCommandCoordinator::new(&store)
            .admit(&CommandAdmission::new(fence, command)?)
            .await?)
    }

    /// Admits conditional offline undo through the store's separate admission gate.
    ///
    /// Selects the current candidate when admission acquires the account permit.
    /// A confirmation-bound UI must use [`Self::admit_undo_for`] to preserve the
    /// exact source the user confirmed instead of selecting a newer candidate.
    ///
    /// # Errors
    /// Rejects missing/stale undo, pending work, identity or capability/quota failures.
    pub async fn admit_undo(
        &self,
        account: &AccountId,
    ) -> Result<CommandAdmissionOutcome, CompositionError> {
        self.admit_undo_with_source(account, None).await
    }

    /// Admits offline conditional undo only for the exact confirmed source.
    ///
    /// Compares account, command ID and revision under the account permit before
    /// building any new intent. The store transaction still compares the full
    /// current candidate and enforces identity, capability, pending-work and
    /// quota guards. Admission needs neither OAuth configuration nor a token;
    /// it does not claim current provider eligibility or successful compensation.
    ///
    /// # Errors
    /// Returns [`CompositionError::NoUndo`] when no candidate remains and
    /// [`CompositionError::Triage`] with [`TriageStoreError::Conflict`] for a
    /// changed or foreign source. Also rejects existing-account, identity,
    /// capability, pending-work, quota or durable admission failures.
    pub async fn admit_undo_for(
        &self,
        account: &AccountId,
        expected_source: &CommandStamp,
    ) -> Result<CommandAdmissionOutcome, CompositionError> {
        self.admit_undo_with_source(account, Some(expected_source))
            .await
    }

    async fn admit_undo_with_source(
        &self,
        account: &AccountId,
        expected_source: Option<&CommandStamp>,
    ) -> Result<CommandAdmissionOutcome, CompositionError> {
        let operation = self.operations.get(account)?;
        let _permit = operation.permit.lock().await;
        let (store, fence) = self.local_context(account).await?;
        let coordinator = MailboxCommandCoordinator::new(&store);
        let candidate = coordinator
            .undo_candidate(&fence)
            .await?
            .ok_or(CompositionError::NoUndo)?;
        if expected_source.is_some_and(|expected| candidate.source() != expected) {
            return Err(TriageStoreError::Conflict.into());
        }
        let metadata = store
            .read_metadata(account)
            .await?
            .ok_or(TriageStoreError::UnknownAccount)?;
        let command = MailboxCommand::compensate(
            metadata.capability(),
            fresh_id()?,
            candidate.compensation().clone(),
        )?;
        Ok(coordinator
            .admit_undo(&UndoAdmission::new(fence, candidate, command)?)
            .await?)
    }

    /// Reads retained status for an exact ID; unknown IDs never enqueue work.
    ///
    /// # Errors
    /// Returns existing-account, identity or durable read failures.
    pub async fn command_lookup(
        &self,
        account: &AccountId,
        id: &MailboxCommandId,
    ) -> Result<Option<RetainedCommand>, CompositionError> {
        let (store, fence) = self.local_context(account).await?;
        Ok(MailboxCommandCoordinator::new(&store)
            .lookup(&fence, &CommandKey::new(account.clone(), id.clone()))
            .await?)
    }

    /// Cancels only a still-Queued command without provider access.
    ///
    /// # Errors
    /// Rejects stale/wrong-account stamps, changed identity or possible dispatch.
    pub async fn cancel_command(
        &self,
        account: &AccountId,
        stamp: &CommandStamp,
    ) -> Result<TerminalCommandSummary, CompositionError> {
        let operation = self.operations.get(account)?;
        let _permit = operation.permit.lock().await;
        let (store, fence) = self.local_context(account).await?;
        Ok(MailboxCommandCoordinator::new(&store)
            .cancel_queued(&CommandPrecondition::new(fence, stamp.clone())?)
            .await?)
    }

    /// Commits explicit warned Abandon locally; this never claims provider rollback.
    ///
    /// # Errors
    /// Rejects stale/wrong-account context or a failed durable disposition.
    pub async fn abandon_command(
        &self,
        account: &AccountId,
        stamp: &CommandStamp,
        confirmation: AbandonConfirmation,
    ) -> Result<TerminalCommandSummary, CompositionError> {
        let operation = self.operations.get(account)?;
        let _permit = operation.permit.lock().await;
        let (store, fence) = self.local_context(account).await?;
        Ok(MailboxCommandCoordinator::new(&store)
            .abandon(
                &CommandPrecondition::new(fence, stamp.clone())?,
                confirmation,
            )
            .await?)
    }

    /// Saves one explicit retry authorization without observing or dispatching.
    ///
    /// # Errors
    /// Rejects stale/foreign state, FIFO or failed retry guards.
    pub async fn authorize_command_retry(
        &self,
        account: &AccountId,
        stamp: &CommandStamp,
    ) -> Result<RetryAuthorization, CompositionError> {
        let operation = self.operations.get(account)?;
        let _permit = operation.permit.lock().await;
        let (store, fence) = self.local_context(account).await?;
        Ok(MailboxCommandCoordinator::new(&store)
            .authorize_retry(&CommandPrecondition::new(fence, stamp.clone())?)
            .await?)
    }

    /// Reads pending/terminal/undo/recovery state without changing Dispatching.
    ///
    /// Does not acquire the online operation permit or require OAuth configuration.
    /// # Errors
    /// Rejects absent/changed identity, invalid grant metadata or failed reads.
    pub async fn command_status(
        &self,
        account: &AccountId,
    ) -> Result<AccountCommandStatus, CompositionError> {
        let (store, fence) = self.local_context(account).await?;
        let coordinator = MailboxCommandCoordinator::new(&store);
        let grant = store
            .load_credential_snapshot(account)
            .map_err(|_error| CompositionError::Authority)?;
        let credential = match grant.credential() {
            StoreCredential::Missing => CredentialPurpose::Missing,
            StoreCredential::Active(_) => CredentialPurpose::Active,
            StoreCredential::RevocationOnly(_) => CredentialPurpose::RevocationOnly,
        };
        Ok(AccountCommandStatus {
            metadata: store
                .read_metadata(account)
                .await?
                .ok_or(TriageStoreError::UnknownAccount)?,
            credential,
            lifecycle: store.lifecycle_metadata(account).await?,
            pending: store.pending_commands(&fence)?,
            terminal: coordinator.terminal_summaries(&fence).await?,
            undo: coordinator.undo_candidate(&fence).await?,
        })
    }

    /// Reconciles once, with optional single dispatch under the exact supplied policy.
    ///
    /// None uses only readonly ports. Some requires current accepted Modify;
    /// Automatic never consumes an explicit ticket or confirms duplicate-create risk.
    /// # Errors
    /// Returns pre-coordinator routing/identity/session/authority failures. Once
    /// coordination starts its report preserves possible sends and durable progress.
    pub async fn drive_commands(
        &self,
        account: &AccountId,
        policy: Option<&CommandWritePolicy>,
    ) -> Result<AccountCommandReport, CompositionError> {
        let operation = self.operations.get(account)?;
        let _permit = operation.permit.lock().await;
        let (store, fence) = self.local_context(account).await?;
        let (session, _) = self.session(account).await?;
        self.check_read_fence(account, &session, &store, &fence)
            .await?;
        let coordinator = MailboxCommandCoordinator::new(&store);
        let command = if let Some(policy) = policy {
            self.check_write_authority(account, &session, &store, &fence)
                .await?;
            let scope = session
                .accepted_scope()
                .ok_or(CompositionError::Authority)?;
            let writer = self
                .mailboxes
                .writer(
                    account.clone(),
                    session.access(),
                    session.capability(),
                    scope,
                )
                .map_err(|_error| CompositionError::Authority)?;
            let guarded = GuardedWriter {
                runtime: self,
                account,
                session: &session,
                store: &store,
                fence: &fence,
                inner: writer,
            };
            coordinator
                .drive(&fence, session.mailbox(), &guarded, policy)
                .await
        } else {
            coordinator
                .observe(&fence, session.mailbox(), session.mailbox())
                .await
        };
        if command_authorization_rejected(&command) {
            self.invalidate_known(account, &operation);
        }
        let convergence = if command.stop() == CommandDriveStop::Terminal {
            Some(CacheConvergenceReport {
                history: self.history_under_permit(account, &session).await,
                catalog: self
                    .catalog_under_permit(account, &session, &store, &fence)
                    .await
                    .map(|_value| ()),
            })
        } else {
            None
        };
        Ok(AccountCommandReport {
            command,
            convergence,
        })
    }

    /// Fetches and persists a complete observed catalog without Modify authority.
    /// # Errors
    /// Returns session, identity, read or atomic cache-replacement failures.
    pub async fn refresh_label_catalog(
        &self,
        account: &AccountId,
    ) -> Result<LabelCatalog, CompositionError> {
        let operation = self.operations.get(account)?;
        let _permit = operation.permit.lock().await;
        let (store, fence) = self.local_context(account).await?;
        let (session, _) = self.session(account).await?;
        self.catalog_under_permit(account, &session, &store, &fence)
            .await
    }
    async fn catalog_under_permit(
        &self,
        account: &AccountId,
        session: &SharedSession,
        store: &SqlCipherMailboxStore,
        fence: &AccountFence,
    ) -> Result<LabelCatalog, CompositionError> {
        self.check_read_fence(account, session, store, fence)
            .await?;
        let catalog = match session.mailbox().read_label_catalog(account).await {
            Ok(catalog) => catalog,
            Err(error) => {
                if error == MetadataReadError::AuthorizationRequired {
                    self.invalidate(account)?;
                }
                return Err(error.into());
            }
        };
        self.check_read_fence(account, session, store, fence)
            .await?;
        store.replace_cached_label_catalog(fence, &catalog)?;
        Ok(catalog)
    }
    async fn check_write_authority(
        &self,
        account: &AccountId,
        session: &SharedSession,
        store: &SqlCipherMailboxStore,
        fence: &AccountFence,
    ) -> Result<(), CompositionError> {
        self.check_read_fence(account, session, store, fence)
            .await?;
        if session.capability() != AccountCapability::Modify || session.accepted_scope().is_none() {
            return Err(CompositionError::Authority);
        }
        Ok(())
    }
}
struct GuardedWriter<'a> {
    runtime: &'a Runtime,
    account: &'a AccountId,
    session: &'a SharedSession,
    store: &'a SqlCipherMailboxStore,
    fence: &'a AccountFence,
    inner: Box<dyn RemoteMailboxCommands>,
}
impl RemoteMailboxCommands for GuardedWriter<'_> {
    fn dispatch<'a>(
        &'a self,
        receipt: &'a DispatchReceipt,
    ) -> BoxFuture<'a, Result<RemoteCommandOutcome, CommandDispatchError>> {
        Box::pin(async move {
            self.runtime
                .check_write_authority(self.account, self.session, self.store, self.fence)
                .await
                .map_err(|_error| CommandDispatchError::AuthorizationRequired)?;
            let outcome = self.inner.dispatch(receipt).await?;
            if matches!(
                outcome.fact(),
                DispatchFact::Rejected(
                    tersa_application::command::CommandRejection::AuthorizationRequired
                )
            ) && let Ok(operation) = self.runtime.operations.get(self.account)
            {
                self.runtime.invalidate_known(self.account, &operation);
            }
            Ok(outcome)
        })
    }
    fn label_catalog<'a>(
        &'a self,
        account: &'a AccountId,
    ) -> BoxFuture<'a, Result<LabelCatalog, MetadataReadError>> {
        self.inner.label_catalog(account)
    }
    fn observe_user_label<'a>(
        &'a self,
        label: &'a UserLabel,
    ) -> BoxFuture<'a, Result<UserLabelObservation, MetadataReadError>> {
        self.inner.observe_user_label(label)
    }
}

fn command_authorization_rejected(report: &CommandDriveReport) -> bool {
    use tersa_application::command_coordinator::CommandCoordinatorError;
    let rejected = |error| {
        matches!(
            error,
            CommandCoordinatorError::Read(MetadataReadError::AuthorizationRequired)
                | CommandCoordinatorError::DispatchDenied(
                    CommandDispatchError::AuthorizationRequired
                )
        )
    };
    matches!(report.stop(), CommandDriveStop::RecoveryRequired(failure) if rejected(failure.error))
        || report
            .attention_failure()
            .is_some_and(|failure| rejected(failure.error))
}
