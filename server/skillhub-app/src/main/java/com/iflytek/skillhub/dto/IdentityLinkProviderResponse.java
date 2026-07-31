package com.iflytek.skillhub.dto;

import com.iflytek.skillhub.auth.identity.IdentityProviderLoginMethodType;
import java.util.Set;

public record IdentityLinkProviderResponse(
        String providerCode,
        String displayName,
        Set<IdentityProviderLoginMethodType> methodTypes
) {
    public IdentityLinkProviderResponse {
        methodTypes = Set.copyOf(methodTypes);
    }
}
