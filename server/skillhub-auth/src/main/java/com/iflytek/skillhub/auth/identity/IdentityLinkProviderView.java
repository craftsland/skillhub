package com.iflytek.skillhub.auth.identity;

import java.util.Set;

public record IdentityLinkProviderView(
        String providerCode,
        String displayName,
        Set<IdentityProviderLoginMethodType> methodTypes
) {
    public IdentityLinkProviderView {
        if (providerCode == null || providerCode.isBlank()) {
            throw new IllegalArgumentException(
                    "Identity provider code is required");
        }
        if (displayName == null || displayName.isBlank()) {
            throw new IllegalArgumentException(
                    "Identity provider display name is required");
        }
        methodTypes = Set.copyOf(methodTypes);
    }
}
