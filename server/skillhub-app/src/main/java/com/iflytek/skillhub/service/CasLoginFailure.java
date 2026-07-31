package com.iflytek.skillhub.service;

/**
 * Stable, credential-free browser failure reported by the CAS login flow.
 */
public enum CasLoginFailure {
    INVALID_STATE,
    TICKET_MISSING,
    VALIDATION_FAILED,
    PROVIDER_UNAVAILABLE,
    ACCESS_DENIED,
    ACCOUNT_PENDING,
    LINK_REQUIRED,
    INTERNAL_ERROR
}
