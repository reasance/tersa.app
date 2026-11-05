-- Capability: 0 ReadOnly, 1 Modify. Purpose: 0 Missing, 1 Active, 2 RevocationOnly.
-- Historical token bytes remain untouched. New typed access uses the broker's smaller bound.
ALTER TABLE account_binding ADD COLUMN capability INTEGER NOT NULL DEFAULT 0 CHECK (capability IN (0, 1));
ALTER TABLE account_binding ADD COLUMN credential_purpose INTEGER NOT NULL DEFAULT 0 CHECK (credential_purpose IN (0, 1, 2));
UPDATE account_binding SET credential_purpose = CASE WHEN refresh_token IS NULL THEN 0 ELSE 1 END;

-- Catalog completeness is separate from membership completeness and remote freshness.
CREATE TABLE mailbox_checkpoint (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    history_cursor TEXT NULL CHECK (history_cursor IS NULL OR (length(CAST(history_cursor AS BLOB)) BETWEEN 1 AND 32 AND history_cursor NOT GLOB '*[^0-9]*' AND (history_cursor = '0' OR substr(history_cursor, 1, 1) != '0'))),
    recovery_required INTEGER NOT NULL DEFAULT 0 CHECK (recovery_required IN (0, 1)),
    catalog_known INTEGER NOT NULL DEFAULT 0 CHECK (catalog_known IN (0, 1)),
    next_fifo INTEGER NOT NULL DEFAULT 1 CHECK (next_fifo >= 1)
) STRICT;
INSERT INTO mailbox_checkpoint (singleton) VALUES (1);

CREATE TABLE provider_labels (
    label_id TEXT PRIMARY KEY NOT NULL CHECK (length(CAST(label_id AS BLOB)) BETWEEN 1 AND 256 AND label_id NOT GLOB '*[^A-Za-z0-9_-]*'),
    name TEXT NOT NULL CHECK (length(CAST(name AS BLOB)) BETWEEN 1 AND 1024),
    kind INTEGER NOT NULL CHECK (kind IN (0, 1))
) STRICT;

-- No row means Unknown. A known row with zero memberships means observed empty.
-- These rows may outlive cached envelopes for pinned/missing command targets.
CREATE TABLE provider_messages (
    message_id TEXT PRIMARY KEY NOT NULL CHECK (length(CAST(message_id AS BLOB)) BETWEEN 1 AND 256),
    observation INTEGER NOT NULL CHECK (observation IN (0, 1))
) STRICT;
CREATE TABLE provider_memberships (
    message_id TEXT NOT NULL,
    label_id TEXT NOT NULL CHECK (length(CAST(label_id AS BLOB)) BETWEEN 1 AND 256 AND label_id NOT GLOB '*[^A-Za-z0-9_-]*'),
    PRIMARY KEY (message_id, label_id),
    FOREIGN KEY (message_id) REFERENCES provider_messages (message_id) ON DELETE CASCADE
) STRICT;

-- Full rows exist only for nonterminal commands plus the single undo candidate.
-- Kinds: message 0, compensation 1, create 2, rename 3, delete 4.
-- Status: Queued 0, Dispatching 1, Ambiguous 2, NeedsAttention 3,
-- Complete 4, Partial 5, Cancelled 6, Abandoned 7.
-- Revisions/tickets are big-endian u64 blobs, preserving the full application range.
CREATE TABLE mailbox_commands (
    command_id TEXT PRIMARY KEY NOT NULL CHECK (length(CAST(command_id AS BLOB)) BETWEEN 1 AND 256 AND command_id NOT GLOB '*[^A-Za-z0-9_-]*'),
    revision BLOB NOT NULL CHECK (length(revision) = 8),
    fifo INTEGER NOT NULL UNIQUE CHECK (fifo >= 1),
    kind INTEGER NOT NULL CHECK (kind BETWEEN 0 AND 4),
    status INTEGER NOT NULL CHECK (status BETWEEN 0 AND 7),
    automatic_attempts INTEGER NOT NULL DEFAULT 0 CHECK (automatic_attempts BETWEEN 0 AND 3),
    retry_revision BLOB NULL CHECK (retry_revision IS NULL OR length(retry_revision) = 8),
    duplicate_risk INTEGER NOT NULL DEFAULT 0 CHECK (duplicate_risk IN (0, 1)),
    dispatch_started INTEGER NOT NULL DEFAULT 0 CHECK (dispatch_started IN (0, 1)),
    dispatch_revision BLOB NULL CHECK (dispatch_revision IS NULL OR length(dispatch_revision) = 8),
    dispatch_authorization INTEGER NULL CHECK (dispatch_authorization IN (0, 1)),
    compensation_guard_revision BLOB NULL CHECK (compensation_guard_revision IS NULL OR length(compensation_guard_revision) = 8),
    dispatch_fact INTEGER NULL CHECK (dispatch_fact BETWEEN 0 AND 6),
    dispatch_label_id TEXT NULL CHECK (dispatch_label_id IS NULL OR (length(CAST(dispatch_label_id AS BLOB)) BETWEEN 1 AND 256 AND dispatch_label_id NOT GLOB '*[^A-Za-z0-9_-]*')),
    dispatch_label_name TEXT NULL CHECK (dispatch_label_name IS NULL OR length(CAST(dispatch_label_name AS BLOB)) BETWEEN 1 AND 1024),
    label_observation INTEGER NULL CHECK (label_observation IN (0, 1)),
    undo_source_id TEXT NULL CHECK (undo_source_id IS NULL OR (length(CAST(undo_source_id AS BLOB)) BETWEEN 1 AND 256 AND undo_source_id NOT GLOB '*[^A-Za-z0-9_-]*')),
    undo_source_revision BLOB NULL CHECK (undo_source_revision IS NULL OR length(undo_source_revision) = 8),
    reconciliation_failure INTEGER NULL CHECK (reconciliation_failure BETWEEN 0 AND 2),
    label_id TEXT NULL CHECK (label_id IS NULL OR (length(CAST(label_id AS BLOB)) BETWEEN 1 AND 256 AND label_id NOT GLOB '*[^A-Za-z0-9_-]*')),
    label_name TEXT NULL CHECK (label_name IS NULL OR length(CAST(label_name AS BLOB)) BETWEEN 1 AND 1024),
    label_progress INTEGER NOT NULL DEFAULT 0 CHECK (label_progress BETWEEN 0 AND 2),
    create_matches INTEGER NULL CHECK (create_matches BETWEEN 0 AND 2),
    observed_label_id TEXT NULL CHECK (observed_label_id IS NULL OR (length(CAST(observed_label_id AS BLOB)) BETWEEN 1 AND 256 AND observed_label_id NOT GLOB '*[^A-Za-z0-9_-]*')),
    observed_label_name TEXT NULL CHECK (observed_label_name IS NULL OR length(CAST(observed_label_name AS BLOB)) BETWEEN 1 AND 1024),
    CHECK ((kind IN (0, 1) AND label_id IS NULL AND label_name IS NULL) OR (kind = 2 AND label_id IS NULL AND label_name IS NOT NULL) OR (kind = 3 AND label_id IS NOT NULL AND label_name IS NOT NULL) OR (kind = 4 AND label_id IS NOT NULL AND label_name IS NULL)),
    CHECK (status != 0 OR automatic_attempts = 0),
    CHECK ((dispatch_started = 0 AND dispatch_revision IS NULL AND dispatch_authorization IS NULL AND dispatch_fact IS NULL) OR (dispatch_started = 1 AND dispatch_revision IS NOT NULL AND dispatch_authorization IS NOT NULL)),
    CHECK (compensation_guard_revision IS NULL OR kind = 1),
    CHECK ((undo_source_id IS NULL AND undo_source_revision IS NULL) OR (kind = 1 AND undo_source_id IS NOT NULL AND undo_source_revision IS NOT NULL)),
    CHECK ((dispatch_fact = 1 AND kind = 2 AND dispatch_label_id IS NOT NULL AND dispatch_label_name IS NOT NULL) OR (coalesce(dispatch_fact, -1) != 1 AND dispatch_label_id IS NULL AND dispatch_label_name IS NULL)),
    CHECK (retry_revision IS NULL OR (retry_revision = revision AND status IN (2, 3)))
) STRICT;
CREATE INDEX mailbox_commands_fifo ON mailbox_commands (status, fifo);

-- Item identities never reference prunable envelopes/catalog definitions.
-- Outcome: NULL pending, 0 desired observed, 1 missing, 2 failed.
-- Observation: NULL unknown, 0 missing, 1 complete known.
CREATE TABLE command_items (
    command_id TEXT NOT NULL,
    message_id TEXT NOT NULL CHECK (length(CAST(message_id AS BLOB)) BETWEEN 1 AND 256),
    outcome INTEGER NULL CHECK (outcome BETWEEN 0 AND 2),
    observation INTEGER NULL CHECK (observation IN (0, 1)),
    dispatch_selected INTEGER NOT NULL DEFAULT 0 CHECK (dispatch_selected IN (0, 1)),
    PRIMARY KEY (command_id, message_id),
    FOREIGN KEY (command_id) REFERENCES mailbox_commands (command_id) ON DELETE CASCADE
) STRICT;
CREATE INDEX command_items_message ON command_items (message_id, command_id);

-- Full reconciliation membership, independent of the catalog and cache lifetime.
CREATE TABLE command_item_memberships (
    command_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    label_id TEXT NOT NULL CHECK (length(CAST(label_id AS BLOB)) BETWEEN 1 AND 256 AND label_id NOT GLOB '*[^A-Za-z0-9_-]*'),
    PRIMARY KEY (command_id, message_id, label_id),
    FOREIGN KEY (command_id, message_id) REFERENCES command_items (command_id, message_id) ON DELETE CASCADE
) STRICT;

-- Field IDs are UNREAD/STARRED/INBOX/TRASH/SPAM or a classified User ID.
-- desired stores the restoration for compensation; expected is its admission-time condition.
-- pre/post retain actual touched evidence, not inferred local unread state.
CREATE TABLE command_fields (
    command_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    field_id TEXT NOT NULL CHECK (length(CAST(field_id AS BLOB)) BETWEEN 1 AND 256 AND field_id NOT GLOB '*[^A-Za-z0-9_-]*'),
    user_label INTEGER NOT NULL CHECK (user_label IN (0, 1)),
    desired INTEGER NOT NULL CHECK (desired IN (0, 1)),
    pre_state INTEGER NULL CHECK (pre_state IN (0, 1)),
    post_state INTEGER NULL CHECK (post_state IN (0, 1)),
    expected_post_state INTEGER NULL CHECK (expected_post_state IN (0, 1)),
    PRIMARY KEY (command_id, message_id, field_id),
    FOREIGN KEY (command_id, message_id) REFERENCES command_items (command_id, message_id) ON DELETE CASCADE,
    CHECK (user_label = 1 OR field_id IN ('UNREAD', 'STARRED', 'INBOX', 'TRASH', 'SPAM'))
) STRICT;

-- Summaries are independently retained (128), without restoring expired command bodies.
CREATE TABLE terminal_commands (
    command_id TEXT PRIMARY KEY NOT NULL CHECK (length(CAST(command_id AS BLOB)) BETWEEN 1 AND 256 AND command_id NOT GLOB '*[^A-Za-z0-9_-]*'),
    revision BLOB NOT NULL CHECK (length(revision) = 8),
    fifo INTEGER NOT NULL UNIQUE CHECK (fifo >= 1),
    status INTEGER NOT NULL CHECK (status BETWEEN 4 AND 7),
    category INTEGER NOT NULL CHECK (category BETWEEN 0 AND 2),
    total INTEGER NOT NULL CHECK (total BETWEEN 1 AND 1000),
    satisfied INTEGER NOT NULL CHECK (satisfied BETWEEN 0 AND 1000),
    missing INTEGER NOT NULL CHECK (missing BETWEEN 0 AND 1000),
    failed INTEGER NOT NULL CHECK (failed BETWEEN 0 AND 1000),
    CHECK (satisfied + missing + failed <= total),
    CHECK (status != 4 OR satisfied = total),
    CHECK (status != 5 OR (satisfied + missing + failed = total AND missing + failed > 0)),
    CHECK (category != 2 OR (total = 1 AND missing = 0))
) STRICT;
CREATE INDEX terminal_commands_fifo ON terminal_commands (fifo);

-- Does not depend on summary retention: the candidate can outlive its summary.
CREATE TABLE mailbox_undo (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    command_id TEXT NOT NULL UNIQUE,
    FOREIGN KEY (command_id) REFERENCES mailbox_commands (command_id)
) STRICT;
