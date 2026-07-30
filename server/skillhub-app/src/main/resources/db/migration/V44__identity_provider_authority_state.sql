CREATE TABLE identity_provider_state (
    provider_code VARCHAR(64) PRIMARY KEY,
    protocol VARCHAR(32) NOT NULL,
    authority VARCHAR(512),
    authority_fingerprint VARCHAR(64),
    state VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMPTZ,
    CONSTRAINT chk_identity_provider_authority_pair
        CHECK (
            (authority IS NULL AND authority_fingerprint IS NULL)
            OR
            (authority IS NOT NULL AND authority_fingerprint IS NOT NULL)
        ),
    CONSTRAINT chk_identity_provider_fingerprint
        CHECK (
            authority_fingerprint IS NULL
            OR authority_fingerprint ~ '^[0-9a-f]{64}$'
        ),
    CONSTRAINT chk_identity_provider_state
        CHECK (
            state IN (
                'READY',
                'DISABLED',
                'MISCONFIGURED',
                'DEGRADED',
                'AUTHORITY_MISMATCH',
                'LEGACY_UNPINNED'
            )
        ),
    CONSTRAINT chk_identity_provider_state_authority
        CHECK (
            (state = 'LEGACY_UNPINNED'
                AND authority IS NULL
                AND authority_fingerprint IS NULL)
            OR
            (state IN ('READY', 'DEGRADED', 'AUTHORITY_MISMATCH')
                AND authority IS NOT NULL
                AND authority_fingerprint IS NOT NULL)
            OR
            state IN ('DISABLED', 'MISCONFIGURED')
        )
);

CREATE INDEX idx_identity_provider_state_status
    ON identity_provider_state(state);
