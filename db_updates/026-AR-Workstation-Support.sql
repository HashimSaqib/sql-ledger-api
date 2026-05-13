-- AR Workstation Support
-- Extends the workstation workflow to support both AP (vendor) and AR (customer) transactions.

-- Track whether a station assignment is for an AP or AR transaction.
-- All existing rows are AP, so DEFAULT 'ap' is safe with no backfill.
ALTER TABLE invoice_station
  ADD COLUMN IF NOT EXISTS transaction_type VARCHAR(10) NOT NULL DEFAULT 'ap';

ALTER TABLE invoice_station_history
  ADD COLUMN IF NOT EXISTS transaction_type VARCHAR(10) NOT NULL DEFAULT 'ap';

-- Extend station_type to support AR-specific and AP-specific defaults.
-- New valid values alongside existing 'default' and 'receipt':
--   'default_ap'  — default station for AP (vendor) transactions only
--   'default_ar'  — default station for AR (customer) transactions only
--   'default'     — default for both AP and AR (existing behaviour, unchanged)
-- The existing idx_stations_unique_type partial unique index already enforces
-- one active station per type, so no additional constraint is needed.

-- Allow workflow_pending notifications to be filtered by transaction type.
-- 'both' preserves existing behaviour for all current subscribers.
ALTER TABLE notification_subscriptions
  ADD COLUMN IF NOT EXISTS transaction_type_filter VARCHAR(10) NOT NULL DEFAULT 'both';

INSERT INTO db_updates (version, last_update) VALUES ('026', 'AR Workstation Support');
