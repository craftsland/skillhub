package com.iflytek.skillhub.auth.identity;

/**
 * Stable failure categories emitted by the unified identity core.
 */
public enum IdentityFailureCode {
    PROVIDER_DISABLED,
    PROVIDER_AUTHORITY_MISMATCH,
    INVALID_IDENTITY_ASSERTION,
    IDENTITY_SUBJECT_MISSING,
    IDENTITY_IDENTIFIER_CONFLICT,
    ACCESS_DENIED,
    ACCOUNT_PENDING,
    ACCOUNT_DISABLED,
    ACCOUNT_MERGED,
    SYSTEM_ACCOUNT_FORBIDDEN
}
