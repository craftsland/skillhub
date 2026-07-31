package com.iflytek.skillhub.auth.identity;

import com.iflytek.skillhub.auth.entity.IdentityLinkOperation;
import com.iflytek.skillhub.auth.entity.IdentityLinkRequestStatus;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record IdentityLinkIntent(
        UUID id,
        IdentityLinkOperation operation,
        IdentityLinkRequestStatus status,
        String providerCode,
        Long targetBindingId,
        Instant expiresAt
) {
    public IdentityLinkIntent {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(providerCode, "providerCode");
        Objects.requireNonNull(expiresAt, "expiresAt");
    }
}
