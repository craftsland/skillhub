package com.iflytek.skillhub.auth.identity;

import java.time.Instant;
import java.util.Objects;

/**
 * Existing-account ownership established by one verified provider exchange.
 *
 * <p>The proof contains no provider subject, credential, token, callback
 * state, or protocol artifact.
 */
public record ExternalIdentityProof(
        String userId,
        String providerCode,
        String protocol,
        Instant authenticatedAt
) {
    public ExternalIdentityProof {
        userId = requireText(userId, "userId", 128);
        providerCode = requireText(
                providerCode,
                "providerCode",
                64);
        protocol = requireText(protocol, "protocol", 32);
        Objects.requireNonNull(
                authenticatedAt,
                "authenticatedAt");
    }

    private static String requireText(
            String value,
            String fieldName,
            int maximumLength) {
        if (value == null
                || value.isBlank()
                || value.length() > maximumLength) {
            throw new IllegalArgumentException(
                    "Invalid external identity proof "
                            + fieldName);
        }
        return value;
    }
}
