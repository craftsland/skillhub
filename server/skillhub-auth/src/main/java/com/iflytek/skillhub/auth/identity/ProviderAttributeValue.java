package com.iflytek.skillhub.auth.identity;

import java.util.Objects;

/**
 * One non-secret attribute value extracted from an already verified provider
 * response.
 */
public record ProviderAttributeValue(
        String value,
        ProviderAttributeTrust trust
) {
    private static final int ADAPTER_VALUE_LIMIT = 8_192;

    public ProviderAttributeValue {
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(trust, "trust");
        if (value.length() > ADAPTER_VALUE_LIMIT) {
            throw new IllegalArgumentException("Provider attribute value is too long");
        }
    }
}
