package com.iflytek.skillhub.auth.identity;

enum IdentityProviderStatus {
    READY,
    DISABLED,
    MISCONFIGURED,
    DEGRADED,
    AUTHORITY_MISMATCH,
    LEGACY_UNPINNED
}
