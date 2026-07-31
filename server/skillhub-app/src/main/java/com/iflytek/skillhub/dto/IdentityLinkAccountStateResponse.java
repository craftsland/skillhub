package com.iflytek.skillhub.dto;

import java.util.List;

public record IdentityLinkAccountStateResponse(
        boolean localPasswordEnabled,
        List<IdentityLinkBindingResponse> linkedProviders,
        List<IdentityLinkProviderResponse> availableProviders
) {
    public IdentityLinkAccountStateResponse {
        linkedProviders = List.copyOf(linkedProviders);
        availableProviders = List.copyOf(availableProviders);
    }
}
