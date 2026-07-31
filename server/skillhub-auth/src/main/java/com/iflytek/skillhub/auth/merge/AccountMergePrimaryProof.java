package com.iflytek.skillhub.auth.merge;

import java.time.Instant;
import java.util.Objects;

/**
 * Non-sensitive metadata for a fresh primary-account proof.
 */
public record AccountMergePrimaryProof(
        String method,
        Instant authenticatedAt,
        Instant expiresAt
) {
    public AccountMergePrimaryProof {
        if (method == null
                || method.isBlank()
                || method.length() > 96) {
            throw new IllegalArgumentException(
                    "Invalid account merge proof method");
        }
        Objects.requireNonNull(
                authenticatedAt,
                "authenticatedAt");
        Objects.requireNonNull(expiresAt, "expiresAt");
        if (!expiresAt.isAfter(authenticatedAt)) {
            throw new IllegalArgumentException(
                    "Account merge proof expiry must be in the future");
        }
    }
}
