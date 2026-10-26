-- Adds the account's own Gmail address to the binding row for display only.
-- It is never logged, and only this account's own database stores it.
ALTER TABLE account_binding ADD COLUMN email_address TEXT NULL CHECK (email_address IS NULL OR (length(CAST(email_address AS BLOB)) BETWEEN 3 AND 320));
