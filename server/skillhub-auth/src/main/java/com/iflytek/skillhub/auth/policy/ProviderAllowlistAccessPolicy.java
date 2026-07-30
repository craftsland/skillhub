package com.iflytek.skillhub.auth.policy;

import java.util.Set;

/**
 * Access policy that limits login to explicitly allowed OAuth providers.
 */
public class ProviderAllowlistAccessPolicy implements AccessPolicy {
    private final Set<String> allowedProviders;

    public ProviderAllowlistAccessPolicy(Set<String> allowedProviders) {
        this.allowedProviders = allowedProviders;
    }

    @Override
    public AccessDecision evaluate(IdentityAccessContext context) {
        return allowedProviders.contains(context.providerCode())
            ? AccessDecision.ALLOW : AccessDecision.DENY;
    }
}
