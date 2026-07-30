package com.iflytek.skillhub.auth.identity;

import java.util.Objects;

record ProvisioningPolicyContext(
        ProviderReference provider,
        ProvisioningMode configuredMode,
        IdentityLoginContext requestContext
) {
    ProvisioningPolicyContext {
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(configuredMode, "configuredMode");
        Objects.requireNonNull(requestContext, "requestContext");
    }
}
