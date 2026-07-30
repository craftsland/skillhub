package com.iflytek.skillhub.auth.identity;

/**
 * Shared interactive-login account-state decision.
 */
public enum AccountLoginDecision {
    ALLOWED,
    PENDING,
    DISABLED,
    MERGED,
    SYSTEM_ACCOUNT
}
