-- Notification System Tables
-- Enables users to subscribe to email notifications for various events

-- Notification subscriptions table
CREATE TABLE notification_subscriptions (
    id SERIAL PRIMARY KEY,
    profile_id INTEGER NOT NULL,  -- from centraldb
    notification_type VARCHAR(100) NOT NULL, -- 'workflow_pending', 'payments_uploaded', etc.
    frequency VARCHAR(50) NOT NULL, -- 'daily', 'weekly', 'monthly', 'custom'
    custom_schedule JSONB, -- for complex schedules: {"days": [1,3,5]}
    delivery_time TIME NOT NULL, -- when to send (e.g., '09:00:00')
    is_active BOOLEAN DEFAULT true,
    last_sent_at TIMESTAMP WITHOUT TIME ZONE,
    email_to VARCHAR(255), -- override recipient email (NULL = use profile email)
    email_cc JSONB, -- JSON array of CC email addresses
    email_bcc JSONB, -- JSON array of BCC email addresses
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for faster lookups
CREATE INDEX idx_notification_subscriptions_profile_type ON notification_subscriptions(profile_id, notification_type);
CREATE INDEX idx_notification_subscriptions_active ON notification_subscriptions(is_active, last_sent_at);

-- Notification history/log
CREATE TABLE notification_history (
    id SERIAL PRIMARY KEY,
    subscription_id INTEGER REFERENCES notification_subscriptions(id) ON DELETE CASCADE,
    profile_id INTEGER NOT NULL,
    notification_type VARCHAR(100) NOT NULL,
    sent_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) NOT NULL, -- 'sent', 'failed', 'skipped'
    record_count INTEGER,
    error_message TEXT
);

-- Indexes for history queries
CREATE INDEX idx_notification_history_profile ON notification_history(profile_id, sent_at);
CREATE INDEX idx_notification_history_subscription ON notification_history(subscription_id);

INSERT INTO db_updates (version, last_update) VALUES ('013', 'Notification System');
