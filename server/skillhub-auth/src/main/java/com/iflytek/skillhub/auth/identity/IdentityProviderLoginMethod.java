package com.iflytek.skillhub.auth.identity;

import com.iflytek.skillhub.auth.provider.ProviderCapability;
import java.util.Objects;

/**
 * Presentation-safe provider metadata. Authority and protocol details remain
 * internal to the identity core.
 */
public record IdentityProviderLoginMethod(
        String providerCode,
        String displayName,
        IdentityProviderLoginMethodType methodType
) {
    public IdentityProviderLoginMethod {
        Objects.requireNonNull(providerCode, "providerCode");
        Objects.requireNonNull(displayName, "displayName");
        Objects.requireNonNull(methodType, "methodType");
        if (providerCode.isBlank() || displayName.isBlank()) {
            throw new IllegalArgumentException(
                    "Provider code and display name are required");
        }
    }

    public IdentityProviderLoginMethod(
            String providerCode,
            String displayName) {
        this(
                providerCode,
                displayName,
                IdentityProviderLoginMethodType.OAUTH_REDIRECT);
    }

    public ProviderCapability capability() {
        return switch (methodType) {
            case OAUTH_REDIRECT, CAS_REDIRECT ->
                    ProviderCapability.BROWSER;
            case DIRECT_PASSWORD -> ProviderCapability.CREDENTIAL;
            case SESSION_BOOTSTRAP -> ProviderCapability.PASSIVE;
        };
    }
}
