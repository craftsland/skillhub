package com.iflytek.skillhub.auth.merge;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Versioned, credential-free preview returned by the merge workflow.
 */
public record AccountMergePreview(
        UUID intentId,
        AccountMergeIntentStatus status,
        int previewVersion,
        Instant expiresAt,
        AccountMergePlan plan
) {
    public AccountMergePreview {
        Objects.requireNonNull(intentId, "intentId");
        Objects.requireNonNull(status, "status");
        if (previewVersion <= 0) {
            throw new IllegalArgumentException(
                    "Invalid account merge preview version");
        }
        Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(plan, "plan");
    }
}
