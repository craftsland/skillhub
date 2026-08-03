package com.iflytek.skillhub.auth.provider;

/**
 * Stable, non-sensitive failure classification reported by an authentication
 * adapter.
 */
public enum ProviderAuthenticationFailureCode {
    UPSTREAM_INVALID_CREDENTIALS,
    UPSTREAM_IDENTITY_NOT_FOUND,
    UPSTREAM_ACCESS_DENIED,
    UPSTREAM_UNAVAILABLE,
    UPSTREAM_MISCONFIGURED,
    TLS_VALIDATION_FAILED,
    UPSTREAM_INVALID_RESPONSE,
    REPLAY_DETECTED
}
