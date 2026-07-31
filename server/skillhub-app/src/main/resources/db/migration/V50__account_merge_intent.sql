CREATE TABLE account_merge_intent (
    id UUID PRIMARY KEY,
    primary_user_id VARCHAR(128) NOT NULL,
    secondary_user_id VARCHAR(128),
    status VARCHAR(32) NOT NULL,
    primary_session_nonce_hash VARCHAR(64) NOT NULL,
    primary_proof_method VARCHAR(96) NOT NULL,
    primary_proof_at TIMESTAMPTZ NOT NULL,
    secondary_proof_method VARCHAR(96),
    secondary_proof_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    preview_version INTEGER,
    preview_digest VARCHAR(64),
    confirmed_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    row_version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_account_merge_intent_primary_user
        FOREIGN KEY (primary_user_id)
        REFERENCES user_account(id),
    CONSTRAINT fk_account_merge_intent_secondary_user
        FOREIGN KEY (secondary_user_id)
        REFERENCES user_account(id),
    CONSTRAINT chk_account_merge_intent_distinct_users
        CHECK (
            secondary_user_id IS NULL
            OR secondary_user_id <> primary_user_id
        ),
    CONSTRAINT chk_account_merge_intent_status
        CHECK (
            status IN (
                'PENDING_SECONDARY_PROOF',
                'READY_FOR_PREVIEW',
                'READY_TO_CONFIRM',
                'COMPLETED',
                'CANCELLED',
                'EXPIRED',
                'FAILED_CONFLICT'
            )
        ),
    CONSTRAINT chk_account_merge_intent_session_hash
        CHECK (
            primary_session_nonce_hash
                ~ '^[0-9a-f]{64}$'
        ),
    CONSTRAINT chk_account_merge_intent_secondary_proof
        CHECK (
            (
                secondary_user_id IS NULL
                AND secondary_proof_method IS NULL
                AND secondary_proof_at IS NULL
            )
            OR
            (
                secondary_user_id IS NOT NULL
                AND secondary_proof_method IS NOT NULL
                AND secondary_proof_at IS NOT NULL
            )
        ),
    CONSTRAINT chk_account_merge_intent_preview
        CHECK (
            (
                preview_version IS NULL
                AND preview_digest IS NULL
            )
            OR
            (
                preview_version > 0
                AND preview_digest
                    ~ '^[0-9a-f]{64}$'
            )
        ),
    CONSTRAINT chk_account_merge_intent_completion
        CHECK (
            (status = 'COMPLETED' AND completed_at IS NOT NULL)
            OR
            (status <> 'COMPLETED' AND completed_at IS NULL)
        ),
    CONSTRAINT chk_account_merge_intent_cancellation
        CHECK (
            (status = 'CANCELLED' AND cancelled_at IS NOT NULL)
            OR
            (status <> 'CANCELLED' AND cancelled_at IS NULL)
        )
);

CREATE UNIQUE INDEX uq_account_merge_intent_active_primary
    ON account_merge_intent(primary_user_id)
    WHERE status IN (
        'PENDING_SECONDARY_PROOF',
        'READY_FOR_PREVIEW',
        'READY_TO_CONFIRM',
        'FAILED_CONFLICT'
    );

CREATE UNIQUE INDEX uq_account_merge_intent_active_secondary
    ON account_merge_intent(secondary_user_id)
    WHERE secondary_user_id IS NOT NULL
      AND status IN (
          'PENDING_SECONDARY_PROOF',
          'READY_FOR_PREVIEW',
          'READY_TO_CONFIRM',
          'FAILED_CONFLICT'
      );

CREATE INDEX idx_account_merge_intent_expiry
    ON account_merge_intent(expires_at)
    WHERE status IN (
        'PENDING_SECONDARY_PROOF',
        'READY_FOR_PREVIEW',
        'READY_TO_CONFIRM',
        'FAILED_CONFLICT'
    );

CREATE INDEX idx_account_merge_intent_secondary_user
    ON account_merge_intent(secondary_user_id)
    WHERE secondary_user_id IS NOT NULL;

CREATE TABLE account_merge_session_revocation (
    id BIGSERIAL PRIMARY KEY,
    merge_intent_id UUID NOT NULL,
    user_id VARCHAR(128) NOT NULL,
    status VARCHAR(16) NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL,
    lease_until TIMESTAMPTZ,
    last_error_code VARCHAR(64),
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_account_merge_session_revocation_intent
        FOREIGN KEY (merge_intent_id)
        REFERENCES account_merge_intent(id),
    CONSTRAINT fk_account_merge_session_revocation_user
        FOREIGN KEY (user_id)
        REFERENCES user_account(id),
    CONSTRAINT uq_account_merge_session_revocation_intent
        UNIQUE (merge_intent_id),
    CONSTRAINT chk_account_merge_session_revocation_status
        CHECK (
            status IN (
                'PENDING',
                'PROCESSING',
                'COMPLETED'
            )
        ),
    CONSTRAINT chk_account_merge_session_revocation_attempt
        CHECK (attempt_count >= 0),
    CONSTRAINT chk_account_merge_session_revocation_lifecycle
        CHECK (
            (
                status = 'PENDING'
                AND lease_until IS NULL
                AND completed_at IS NULL
            )
            OR
            (
                status = 'PROCESSING'
                AND lease_until IS NOT NULL
                AND completed_at IS NULL
            )
            OR
            (
                status = 'COMPLETED'
                AND lease_until IS NULL
                AND completed_at IS NOT NULL
            )
        )
);

CREATE INDEX idx_account_merge_session_revocation_due
    ON account_merge_session_revocation(
        next_attempt_at,
        id
    )
    WHERE status IN ('PENDING', 'PROCESSING');
