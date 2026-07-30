package com.iflytek.skillhub.dto;

import com.iflytek.skillhub.auth.identity.IdentityProviderLoginMethodType;
import java.util.Set;

public record IdentityLinkBindingResponse(
        long bindingId,
        String providerCode,
        String displayName,
        Set<IdentityProviderLoginMethodType> methodTypes,
        boolean usable,
        boolean canUnlink
) {
    public IdentityLinkBindingResponse {
        methodTypes = Set.copyOf(methodTypes);
    }
}
