package com.iflytek.skillhub.auth.identity;

import java.util.List;

public record IdentityLinkAccountState(
        boolean localPasswordEnabled,
        List<IdentityLinkBindingView> linkedProviders,
        List<IdentityLinkProviderView> availableProviders
) {
    public IdentityLinkAccountState {
        linkedProviders = List.copyOf(linkedProviders);
        availableProviders = List.copyOf(availableProviders);
    }
}
