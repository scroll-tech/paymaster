-- +goose Up
-- +goose StatementBegin

CREATE TABLE policy
(
    id              BIGSERIAL       PRIMARY KEY,
    api_key         VARCHAR(64)     NOT NULL,
    policy_id       BIGINT          NOT NULL,
    policy_name     VARCHAR(255)    NOT NULL,
    limits          JSON            NOT NULL,

    created_at      TIMESTAMP(0)    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP(0)    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at      TIMESTAMP(0)    DEFAULT NULL
);

CREATE UNIQUE INDEX unique_idx_api_key_policy_id ON policy(api_key, policy_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_api_key ON policy(api_key) WHERE deleted_at IS NULL;

COMMENT ON COLUMN policy.limits IS 'JSON containing max_eth_per_wallet_per_window, time_window_hours';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS policy;
-- +goose StatementEnd
