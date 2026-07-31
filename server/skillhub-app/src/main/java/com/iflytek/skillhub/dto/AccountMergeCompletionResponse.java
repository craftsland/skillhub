package com.iflytek.skillhub.dto;

import com.iflytek.skillhub.auth.merge.AccountMergeIntentStatus;
import java.time.Instant;
import java.util.UUID;

public record AccountMergeCompletionResponse(
        UUID intentId,
        AccountMergeIntentStatus status,
        Instant completedAt
) {
}
