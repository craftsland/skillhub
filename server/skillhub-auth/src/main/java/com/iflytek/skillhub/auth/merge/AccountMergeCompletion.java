package com.iflytek.skillhub.auth.merge;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Non-secret completion receipt for one consumed merge intent.
 */
public record AccountMergeCompletion(
        UUID intentId,
        AccountMergeIntentStatus status,
        Instant completedAt
) {
    public AccountMergeCompletion {
        Objects.requireNonNull(intentId, "intentId");
        if (status != AccountMergeIntentStatus.COMPLETED) {
            throw new IllegalArgumentException(
                    "Account merge completion must be completed");
        }
        Objects.requireNonNull(completedAt, "completedAt");
    }
}
