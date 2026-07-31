package com.iflytek.skillhub.dto;

import com.iflytek.skillhub.auth.merge.AccountMergeIntentStatus;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record AccountMergeIntentResponse(
        UUID id,
        AccountMergeIntentStatus status,
        Instant expiresAt,
        List<AccountMergeAuthenticationMethodResponse>
                secondaryMethods
) {
    public AccountMergeIntentResponse {
        secondaryMethods = List.copyOf(secondaryMethods);
    }
}
