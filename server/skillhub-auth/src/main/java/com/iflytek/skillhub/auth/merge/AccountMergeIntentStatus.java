package com.iflytek.skillhub.auth.merge;

/**
 * Server-side state of a safe account-merge intent.
 */
public enum AccountMergeIntentStatus {
    PENDING_SECONDARY_PROOF,
    READY_FOR_PREVIEW,
    READY_TO_CONFIRM,
    COMPLETED,
    CANCELLED,
    EXPIRED,
    FAILED_CONFLICT;

    public boolean isActive() {
        return this == PENDING_SECONDARY_PROOF
                || this == READY_FOR_PREVIEW
                || this == READY_TO_CONFIRM
                || this == FAILED_CONFLICT;
    }
}
