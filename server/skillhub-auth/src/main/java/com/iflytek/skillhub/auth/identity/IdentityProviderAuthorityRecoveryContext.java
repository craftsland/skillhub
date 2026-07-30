package com.iflytek.skillhub.auth.identity;

import java.util.Objects;

/**
 * Authenticated operator and bounded request metadata for an authority
 * recovery audit.
 */
public record IdentityProviderAuthorityRecoveryContext(
        String actorUserId,
        String requestId,
        String clientIp,
        String userAgent
) {
    public IdentityProviderAuthorityRecoveryContext {
        Objects.requireNonNull(actorUserId, "actorUserId");
        if (actorUserId.isBlank() || actorUserId.length() > 128) {
            throw new IllegalArgumentException("Invalid actor user id");
        }
        validateLength(requestId, 64, "requestId");
        validateLength(clientIp, 64, "clientIp");
        validateLength(userAgent, 512, "userAgent");
    }

    private static void validateLength(
            String value,
            int maximum,
            String field) {
        if (value != null && value.length() > maximum) {
            throw new IllegalArgumentException(field + " is too long");
        }
    }
}
