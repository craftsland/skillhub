package com.iflytek.skillhub.auth.merge;

import java.time.Instant;
import java.util.UUID;

/**
 * Non-sensitive public projection of an account-merge intent.
 */
public record AccountMergeIntent(
        UUID id,
        AccountMergeIntentStatus status,
        Instant expiresAt
) {
}
