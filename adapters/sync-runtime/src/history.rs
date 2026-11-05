// This Source Code Form is subject to the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! History orchestration followed by a freshly fenced, bounded body phase.

use crate::{CompositionError, Runtime, SharedSession};
use tersa_application::{
    history_sync::{
        HistoryBodyPlan, HistoryRecoveryReason, HistorySync, HistorySyncReport, HistorySyncStop,
    },
    identity::{AccountIdentityHasher, AccountIdentityStore, AccountProfile, normalize_subject},
    lifecycle::AccountLifecycleStore,
    mailbox::{AccountId, MailboxReader, MailboxStore, RemoteMailbox, StoreLimit},
    mailbox_state::TriageStoreError,
    profile::AccountFence,
};
use tersa_store_sqlcipher::SqlCipherMailboxStore;

/// Separates optional body work from already committed metadata/cursor progress.
#[derive(Debug)]
pub struct BodyPhaseReport {
    /// Current retained recent envelopes selected, at most 25.
    pub selected: usize,
    /// Exact-ID body requests started, at most 25.
    pub requests: usize,
    /// Conditional cache writes that actually retained a body.
    pub cached: usize,
    /// True when no body plan could safely be executed.
    pub skipped: bool,
    /// First body-phase failure; earlier confirmed progress remains valid.
    pub failure: Option<CompositionError>,
}
impl BodyPhaseReport {
    fn skipped() -> Self {
        Self {
            selected: 0,
            requests: 0,
            cached: 0,
            skipped: true,
            failure: None,
        }
    }
}
/// Keeps confirmed History progress separate from optional body failures.
#[derive(Debug)]
pub struct AccountHistoryReport {
    /// Coordinator-owned metadata and cursor progress, including bounded stops.
    pub metadata: HistorySyncReport,
    /// Optional bounded body work; never rolls metadata progress back.
    pub bodies: BodyPhaseReport,
    /// Fully completed cycle timestamp update; failure is post-metadata and never rollback.
    pub freshness: Option<Result<(), CompositionError>>,
}
impl Runtime {
    /// Runs one bounded History cycle and a separate at-most-25 body phase.
    ///
    /// Caller holds the installation lock. Account serialization spans identity
    /// admission, metadata and bodies. This API never retries writes or hides
    /// History progress inside the legacy snapshot report.
    ///
    /// # Errors
    /// Returns routing/session/identity-admission failures before History starts.
    /// Later failures remain in the returned metadata/body reports.
    pub async fn sync_history(
        &self,
        account: &AccountId,
    ) -> Result<AccountHistoryReport, CompositionError> {
        let operation = self.operations.get(account)?;
        let _permit = operation.permit.lock().await;
        let (session, _) = self.session(account).await?;
        self.history_under_permit(account, &session).await
    }

    pub(crate) async fn history_under_permit(
        &self,
        account: &AccountId,
        session: &SharedSession,
    ) -> Result<AccountHistoryReport, CompositionError> {
        let operation = self.operations.get(account)?;
        if !self.session_is_current(account, session)? || !session.unexpired() {
            return Err(CompositionError::Authority);
        }
        let store = self.installation.open_store(account)?;
        let identity =
            crate::gate::run_identity_gate(account, session, &self.hasher, &store).await?;
        let fence = AccountFence::new(account.clone(), identity);
        let metadata = HistorySync::new(session.mailbox(), &store)
            .sync(&fence)
            .await;
        let mut bodies = BodyPhaseReport::skipped();
        let rejected = authorization_recovery(&metadata);
        if rejected {
            self.invalidate_known(account, &operation);
        }
        if !rejected
            && !identity_recovery(&metadata)
            && let Some(plan) = metadata.body_plan()
        {
            bodies.skipped = false;
            if let Err(error) = self
                .body_phase(account, session, &store, plan, &mut bodies)
                .await
            {
                bodies.failure = Some(error);
            }
        }
        if bodies.failure.as_ref().is_some_and(|error| {
            matches!(
                error,
                CompositionError::Flow(crate::FlowError::Fetch(crate::GatedFetchError::Remote(
                    tersa_application::mailbox::RemoteMailboxError::AuthorizationRequired
                )))
            )
        }) {
            self.invalidate_known(account, &operation);
        }
        let freshness = if bodies.failure.is_none()
            && matches!(
                metadata.stop(),
                HistorySyncStop::CaughtUp | HistorySyncStop::SnapshotCommitted(_)
            ) {
            Some(
                self.record_history_freshness(account, session, &store, &fence)
                    .await,
            )
        } else {
            None
        };
        Ok(AccountHistoryReport {
            metadata,
            bodies,
            freshness,
        })
    }

    async fn body_phase(
        &self,
        account: &AccountId,
        session: &SharedSession,
        store: &SqlCipherMailboxStore,
        plan: &HistoryBodyPlan,
        report: &mut BodyPhaseReport,
    ) -> Result<(), CompositionError> {
        self.check_read_fence(account, session, store, plan.fence())
            .await?;
        let limit = StoreLimit::new(
            u16::try_from(plan.limit()).map_err(|_error| CompositionError::Authority)?,
        )
        .map_err(|_error| CompositionError::Authority)?;
        let recent = store.list_envelopes(account, limit).await?;
        report.selected = recent.len();
        let ids: Vec<_> = recent
            .into_iter()
            .map(|row| row.message_id().clone())
            .collect();
        let missing = store.uncached_message_ids(account, &ids).await?;
        for id in missing {
            self.check_read_fence(account, session, store, plan.fence())
                .await?;
            report.requests += 1;
            let message = session
                .fetch_message(account, &id)
                .await
                .map_err(crate::GatedFetchError::Remote)
                .map_err(crate::FlowError::Fetch)?;
            if message.envelope().message_id() != &id {
                return Err(CompositionError::Contract(
                    tersa_application::mailbox_state::ContractError::WrongTarget,
                ));
            }
            self.check_read_fence(account, session, store, plan.fence())
                .await?;
            if store
                .cache_message_if_present(account, &message, plan.fence().identity())
                .await?
            {
                report.cached += 1;
            }
        }
        Ok(())
    }

    async fn record_history_freshness(
        &self,
        account: &AccountId,
        session: &SharedSession,
        store: &SqlCipherMailboxStore,
        fence: &AccountFence,
    ) -> Result<(), CompositionError> {
        self.check_read_fence(account, session, store, fence)
            .await?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|value| i64::try_from(value.as_millis()).ok())
            .ok_or(CompositionError::Store(
                tersa_application::mailbox::MailboxStoreError::Storage,
            ))?;
        store.record_successful_sync(account, now).await?;
        Ok(())
    }

    pub(crate) async fn check_read_fence(
        &self,
        account: &AccountId,
        session: &SharedSession,
        store: &SqlCipherMailboxStore,
        fence: &AccountFence,
    ) -> Result<(), CompositionError> {
        let fresh = self
            .hasher
            .hash(account, &normalize_subject(session.subject()))
            .map_err(tersa_application::identity::GateError::Hasher)?;
        if fence.account_id() != account
            || fence.identity() != &fresh
            || store.load_identity(account).await?.as_ref() != Some(fence.identity())
        {
            return Err(CompositionError::IdentityChanged);
        }
        if !session.unexpired() || !self.session_is_current(account, session)? {
            return Err(CompositionError::Authority);
        }
        Ok(())
    }
}
fn identity_recovery(report: &HistorySyncReport) -> bool {
    matches!(
        report.stop(),
        HistorySyncStop::RecoveryRequired(HistoryRecoveryReason::Store(
            TriageStoreError::IdentityChanged
        ))
    )
}

fn authorization_recovery(report: &HistorySyncReport) -> bool {
    matches!(
        report.stop(),
        HistorySyncStop::RecoveryRequired(
            HistoryRecoveryReason::Read(
                tersa_application::mailbox_state::MetadataReadError::AuthorizationRequired
            ) | HistoryRecoveryReason::Feed(tersa_application::history::HistoryFeedError::Read(
                tersa_application::mailbox_state::MetadataReadError::AuthorizationRequired
            ))
        )
    )
}
