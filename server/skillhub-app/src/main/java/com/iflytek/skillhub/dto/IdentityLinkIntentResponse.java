package com.iflytek.skillhub.dto;

import com.iflytek.skillhub.auth.entity.IdentityLinkOperation;
import com.iflytek.skillhub.auth.entity.IdentityLinkRequestStatus;
import java.time.Instant;
import java.util.UUID;

public record IdentityLinkIntentResponse(
        UUID id,
        IdentityLinkOperation operation,
        IdentityLinkRequestStatus status,
        String providerCode,
        Long targetBindingId,
        Instant expiresAt
) {
}
