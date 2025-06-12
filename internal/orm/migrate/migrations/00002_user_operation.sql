-- +goose Up
-- +goose StatementBegin

CREATE TABLE user_operation
(
    id              BIGSERIAL       PRIMARY KEY,
    api_key_hash    VARCHAR(66)     NOT NULL,
    policy_id       BIGINT          NOT NULL,
    sender          VARCHAR(42)     NOT NULL,
    nonce           BIGINT          NOT NULL,
    wei_amount      BIGINT          NOT NULL,
    status          SMALLINT        NOT NULL DEFAULT 1,

    created_at      TIMESTAMP(0)    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP(0)    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at      TIMESTAMP(0)    DEFAULT NULL
);

ALTER TABLE user_operation ADD CONSTRAINT check_status CHECK (status IN (1, 2));

COMMENT ON COLUMN user_operation.status IS '1=stub_data_provided (pm_getPaymasterStubData), 2=paymaster_data_provided (pm_getPaymasterData)';
COMMENT ON COLUMN user_operation.api_key_hash IS 'Keccak256 hash of the API key';

CREATE UNIQUE INDEX unique_idx_api_key_hash_policy_id_sender_nonce ON user_operation(api_key_hash, policy_id, sender, nonce);
CREATE INDEX idx_api_key_hash_policy_id_sender_updated_at ON user_operation(api_key_hash, policy_id, sender, updated_at) WHERE deleted_at IS NULL;

-- +goose StatementEnd
