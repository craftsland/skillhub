package com.iflytek.skillhub.auth.identity;

import com.iflytek.skillhub.auth.identity.IdentityProviderLoginMethodType;
import java.util.Set;

public record IdentityLinkBindingView(
        long bindingId,
        String providerCode,
        String displayName,
        Set<IdentityProviderLoginMethodType> methodTypes,
        boolean usable,
        boolean canUnlink
) {
    public IdentityLinkBindingView {
        if (bindingId <= 0) {
            throw new IllegalArgumentException(
                    "Identity binding id must be positive");
        }
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
