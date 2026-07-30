-- Binding V2 expand migration.
--
-- This migration intentionally does not install the deferred "at least one
-- active primary subject" trigger. During a rolling upgrade, PR 1 pods must
-- remain able to insert identity_binding rows without writing the new subject
-- table. The trigger is a separate contract-gate migration after all old pods
-- have exited and the preflight has passed.

ALTER TABLE identity_binding
    ADD COLUMN status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE',
    ADD COLUMN last_authenticated_at TIMESTAMPTZ,
    ADD COLUMN last_synchronized_at TIMESTAMPTZ,
    ADD COLUMN revoked_at TIMESTAMPTZ,
    ADD COLUMN revoked_by VARCHAR(128),
    ADD COLUMN revocation_reason VARCHAR(256),
    ADD CONSTRAINT chk_identity_binding_status
        CHECK (status IN ('ACTIVE', 'REVOKED')),
    ADD CONSTRAINT chk_identity_binding_revocation
        CHECK (
            (status = 'ACTIVE'
                AND revoked_at IS NULL
                AND revoked_by IS NULL
                AND revocation_reason IS NULL)
            OR
            (status = 'REVOKED' AND revoked_at IS NOT NULL)
        ),
    ADD CONSTRAINT uq_identity_binding_id_provider
        UNIQUE (id, provider_code);

DO $$
DECLARE
    duplicate_summary TEXT;
BEGIN
    SELECT string_agg(
        format('%s/%s (%s bindings)', user_id, provider_code, binding_count),
        ', ' ORDER BY user_id, provider_code)
    INTO duplicate_summary
    FROM (
        SELECT user_id, provider_code, COUNT(*) AS binding_count
        FROM identity_binding
        GROUP BY user_id, provider_code
        HAVING COUNT(*) > 1
        LIMIT 20
    ) duplicates;

    IF duplicate_summary IS NOT NULL THEN
        RAISE EXCEPTION
            'Binding V2 preflight failed: multiple active bindings for user/provider: %',
            duplicate_summary;
    END IF;
END
$$;

CREATE UNIQUE INDEX uq_identity_binding_active_user_provider
    ON identity_binding(user_id, provider_code)
    WHERE status = 'ACTIVE';

CREATE TABLE identity_binding_subject (
    id BIGSERIAL PRIMARY KEY,
    binding_id BIGINT NOT NULL,
    provider_code VARCHAR(64) NOT NULL,
    subject_type VARCHAR(64) NOT NULL,
    subject_value VARCHAR(512) NOT NULL,
    is_primary BOOLEAN NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT fk_identity_binding_subject_binding_provider
        FOREIGN KEY (binding_id, provider_code)
        REFERENCES identity_binding(id, provider_code)
        ON DELETE CASCADE,
    CONSTRAINT chk_identity_binding_subject_type
        CHECK (subject_type ~ '^[a-z][a-z0-9_]{0,63}$'),
    CONSTRAINT chk_identity_binding_subject_value
        CHECK (subject_value <> ''),
    CONSTRAINT chk_identity_binding_subject_status
        CHECK (status IN ('ACTIVE', 'REVOKED')),
    CONSTRAINT chk_identity_binding_subject_revocation
        CHECK (
            (status = 'ACTIVE' AND revoked_at IS NULL)
            OR
            (status = 'REVOKED'
                AND revoked_at IS NOT NULL
                AND is_primary = FALSE)
        )
);

INSERT INTO identity_binding_subject (
    binding_id,
    provider_code,
    subject_type,
    subject_value,
    is_primary,
    status,
    created_at,
    last_seen_at
)
SELECT
    id,
    provider_code,
    'legacy_subject',
    subject,
    TRUE,
    'ACTIVE',
    created_at,
    updated_at
FROM identity_binding;

CREATE UNIQUE INDEX uq_identity_binding_subject_active_identity
    ON identity_binding_subject(
        provider_code,
        subject_type,
        subject_value
    )
    WHERE status = 'ACTIVE';

CREATE UNIQUE INDEX uq_identity_binding_subject_active_primary
    ON identity_binding_subject(binding_id)
    WHERE status = 'ACTIVE' AND is_primary = TRUE;

CREATE INDEX idx_identity_binding_subject_binding
    ON identity_binding_subject(binding_id, status);

CREATE INDEX idx_identity_binding_subject_lookup
    ON identity_binding_subject(
        provider_code,
        subject_type,
        subject_value,
        status
    );
