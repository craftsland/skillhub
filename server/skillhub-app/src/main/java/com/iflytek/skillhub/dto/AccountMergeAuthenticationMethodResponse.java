package com.iflytek.skillhub.dto;

import java.util.Objects;

/**
 * Presentation-safe fresh-authentication capability.
 */
public record AccountMergeAuthenticationMethodResponse(
        String providerCode,
        String displayName,
        String methodType
) {
    public AccountMergeAuthenticationMethodResponse {
        providerCode = requireText(
                providerCode,
                "providerCode");
        displayName = requireText(
                displayName,
                "displayName");
        methodType = requireText(
                methodType,
                "methodType");
    }

    private static String requireText(
            String value,
            String fieldName) {
        Objects.requireNonNull(value, fieldName);
        if (value.isBlank()) {
            throw new IllegalArgumentException(
                    fieldName + " is required");
        }
        return value;
    }
}
