CREATE TABLE user_profile_field_source (
    user_id VARCHAR(128) NOT NULL,
    field_name VARCHAR(32) NOT NULL,
    source_type VARCHAR(32) NOT NULL,
    provider_code VARCHAR(64),
    assurance VARCHAR(32),
    last_synchronized_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, field_name),
    CONSTRAINT fk_user_profile_field_source_user
        FOREIGN KEY (user_id)
        REFERENCES user_account(id)
        ON DELETE CASCADE,
    CONSTRAINT fk_user_profile_field_source_provider
        FOREIGN KEY (provider_code)
        REFERENCES identity_provider_state(provider_code),
    CONSTRAINT chk_user_profile_field_name
        CHECK (field_name IN ('displayName', 'email', 'avatarUrl')),
    CONSTRAINT chk_user_profile_field_source_type
        CHECK (
            source_type IN (
                'PROVIDER',
                'USER',
                'ADMIN',
                'LEGACY_LOCAL'
            )
        ),
    CONSTRAINT chk_user_profile_field_assurance
        CHECK (
            assurance IS NULL
            OR assurance IN (
                'UNVERIFIED',
                'PROVIDER_ASSERTED',
                'VERIFIED',
                'AUTHORITATIVE'
            )
        ),
    CONSTRAINT chk_user_profile_field_provider_source
        CHECK (
            (
                source_type = 'PROVIDER'
                AND provider_code IS NOT NULL
                AND assurance IS NOT NULL
                AND last_synchronized_at IS NOT NULL
            )
            OR
            (
                source_type <> 'PROVIDER'
                AND provider_code IS NULL
                AND assurance IS NULL
                AND last_synchronized_at IS NULL
            )
        )
);

CREATE INDEX idx_user_profile_field_source_provider
    ON user_profile_field_source(provider_code)
    WHERE provider_code IS NOT NULL;

INSERT INTO user_profile_field_source (
    user_id,
    field_name,
    source_type,
    updated_at
)
SELECT
    id,
    'displayName',
    'LEGACY_LOCAL',
    updated_at
FROM user_account;

INSERT INTO user_profile_field_source (
    user_id,
    field_name,
    source_type,
    updated_at
)
SELECT
    id,
    'email',
    'LEGACY_LOCAL',
    updated_at
FROM user_account
WHERE email IS NOT NULL
  AND btrim(email) <> '';

INSERT INTO user_profile_field_source (
    user_id,
    field_name,
    source_type,
    updated_at
)
SELECT
    id,
    'avatarUrl',
    'LEGACY_LOCAL',
    updated_at
FROM user_account
WHERE avatar_url IS NOT NULL
  AND btrim(avatar_url) <> '';
