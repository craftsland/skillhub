CREATE TABLE identity_link_request (
    id UUID PRIMARY KEY,
    primary_user_id VARCHAR(128) NOT NULL,
    operation VARCHAR(16) NOT NULL,
    provider_code VARCHAR(64) NOT NULL,
    target_binding_id BIGINT,
    state_hash VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL,
    reauthentication_method VARCHAR(96),
    reauthenticated_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    row_version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_identity_link_request_user
        FOREIGN KEY (primary_user_id)
        REFERENCES user_account(id)
        ON DELETE CASCADE,
    CONSTRAINT fk_identity_link_request_binding
        FOREIGN KEY (target_binding_id)
        REFERENCES identity_binding(id),
    CONSTRAINT chk_identity_link_request_operation
        CHECK (operation IN ('LINK', 'UNLINK')),
    CONSTRAINT chk_identity_link_request_state_hash
        CHECK (state_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_identity_link_request_status
        CHECK (
            status IN (
                'PENDING_REAUTHENTICATION',
                'READY',
                'COMPLETED',
                'EXPIRED',
                'CANCELLED'
            )
        ),
    CONSTRAINT chk_identity_link_request_target
        CHECK (
            (operation = 'LINK' AND target_binding_id IS NULL)
            OR
            (operation = 'UNLINK' AND target_binding_id IS NOT NULL)
        ),
    CONSTRAINT chk_identity_link_request_reauthentication
        CHECK (
            (
                status = 'PENDING_REAUTHENTICATION'
                AND reauthentication_method IS NULL
                AND reauthenticated_at IS NULL
            )
            OR
            (
                status IN ('READY', 'COMPLETED')
                AND reauthentication_method IS NOT NULL
                AND reauthenticated_at IS NOT NULL
            )
            OR
            status IN ('EXPIRED', 'CANCELLED')
        ),
    CONSTRAINT chk_identity_link_request_completion
        CHECK (
            (status = 'COMPLETED' AND completed_at IS NOT NULL)
            OR
            (status <> 'COMPLETED' AND completed_at IS NULL)
        ),
    CONSTRAINT chk_identity_link_request_cancellation
        CHECK (
            (status = 'CANCELLED' AND cancelled_at IS NOT NULL)
            OR
            (status <> 'CANCELLED' AND cancelled_at IS NULL)
        )
);

CREATE UNIQUE INDEX uq_identity_link_request_active_user
    ON identity_link_request(primary_user_id)
    WHERE status IN ('PENDING_REAUTHENTICATION', 'READY');

CREATE INDEX idx_identity_link_request_expiry
    ON identity_link_request(expires_at)
    WHERE status IN ('PENDING_REAUTHENTICATION', 'READY');

CREATE INDEX idx_identity_link_request_binding
    ON identity_link_request(target_binding_id)
    WHERE target_binding_id IS NOT NULL;

ALTER TABLE identity_binding
    DROP CONSTRAINT identity_binding_provider_code_subject_key;

CREATE UNIQUE INDEX uq_identity_binding_active_provider_subject
    ON identity_binding(provider_code, subject)
    WHERE status = 'ACTIVE';
