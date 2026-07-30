package com.iflytek.skillhub.auth.identity;

import java.util.Objects;

/**
 * Presentation-safe provider metadata. Authority and protocol details remain
 * internal to the identity core.
 */
public record IdentityProviderLoginMethod(
        String providerCode,
        String displayName
) {
    public IdentityProviderLoginMethod {
        Objects.requireNonNull(providerCode, "providerCode");
        Objects.requireNonNull(displayName, "displayName");
        if (providerCode.isBlank() || displayName.isBlank()) {
            throw new IllegalArgumentException(
                    "Provider code and display name are required");
        }
    }
}
