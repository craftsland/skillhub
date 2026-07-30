package com.iflytek.skillhub.auth.identity;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.stereotype.Service;

@Service
class DefaultIdentityProviderReadinessService
        implements IdentityProviderReadinessService {

    private final TrustedProviderRouteResolver routeResolver;
    private final TrustedProviderDescriptorSource descriptorSource;
    private final ProviderAuthorityLockService authorityLockService;

    DefaultIdentityProviderReadinessService(
            TrustedProviderRouteResolver routeResolver,
            TrustedProviderDescriptorSource descriptorSource,
            ProviderAuthorityLockService authorityLockService) {
        this.routeResolver = routeResolver;
        this.descriptorSource = descriptorSource;
        this.authorityLockService = authorityLockService;
    }

    @Override
    public void requireReady(ClientRegistration registration) {
        ResolvedProviderHandle handle = routeResolver.resolve(registration);
        ProviderDescriptor descriptor = descriptorSource.require(handle);
        authorityLockService.requirePinnedAuthority(descriptor);
    }
}
