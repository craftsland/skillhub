package com.iflytek.skillhub.auth.identity;

import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

class DefaultIdentityProviderReadinessServiceTest {

    @Test
    void resolvesServerRouteBeforeCheckingPersistedReadiness() {
        TrustedProviderRouteResolver routeResolver =
                mock(TrustedProviderRouteResolver.class);
        TrustedProviderDescriptorSource descriptorSource =
                mock(TrustedProviderDescriptorSource.class);
        ProviderAuthorityLockService authorityLockService =
                mock(ProviderAuthorityLockService.class);
        ClientRegistration registration = mock(ClientRegistration.class);
        ResolvedProviderHandle handle =
                new DefaultResolvedProviderHandle("github");
        ProviderDescriptor descriptor = descriptor();
        when(routeResolver.resolve(registration)).thenReturn(handle);
        when(descriptorSource.require(handle)).thenReturn(descriptor);
        DefaultIdentityProviderReadinessService service =
                new DefaultIdentityProviderReadinessService(
                        routeResolver,
                        descriptorSource,
                        authorityLockService);

        service.requireReady(registration);

        InOrder order = inOrder(
                routeResolver,
                descriptorSource,
                authorityLockService);
        order.verify(routeResolver).resolve(registration);
        order.verify(descriptorSource).require(handle);
        order.verify(authorityLockService)
                .requirePinnedAuthority(descriptor);
    }

    private static ProviderDescriptor descriptor() {
        return new ProviderDescriptor(
                "github",
                "oauth2-github",
                "https://github.com",
                "GitHub",
                "github_user_id",
                Set.of("github_user_id"),
                SubjectCanonicalizer.DECIMAL,
                List.of("login"),
                List.of("email"),
                List.of("avatar_url"),
                EmailAssurance.VERIFIED);
    }
}
