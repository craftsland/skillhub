package com.iflytek.skillhub.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.identity.IdentityProviderRegistry;
import com.iflytek.skillhub.auth.identity.IdentityProviderLoginMethod;
import com.iflytek.skillhub.auth.identity.IdentityProviderLoginMethodType;
import com.iflytek.skillhub.config.AuthSessionBootstrapProperties;
import com.iflytek.skillhub.config.DirectAuthProperties;
import java.util.List;
import org.junit.jupiter.api.Test;

class AuthMethodCatalogTest {

    @Test
    void catalogsOnlyProvidersApprovedByTheIdentityCore() {
        IdentityProviderRegistry registry =
            mock(IdentityProviderRegistry.class);
        when(registry.listReadyProviders()).thenReturn(List.of(
            new IdentityProviderLoginMethod("valid", "Valid")
        ));
        when(registry.listReadyLoginMethods()).thenReturn(List.of(
            new IdentityProviderLoginMethod("valid", "Valid")
        ));

        AuthMethodCatalog catalog = new AuthMethodCatalog(
            registry,
            new DirectAuthProperties(),
            new AuthSessionBootstrapProperties()
        );

        assertThat(catalog.listOAuthProviders(null))
            .extracting(provider -> provider.id())
            .containsExactly("valid");
        assertThat(catalog.listMethods(null))
            .extracting(method -> method.id())
            .containsExactly("local-password", "oauth-valid");
    }

    @Test
    void listMethodsShouldUseProviderDisplayNamesForCompatibleAuthMethods() {
        DirectAuthProperties directAuthProperties = new DirectAuthProperties();
        directAuthProperties.setEnabled(true);
        AuthSessionBootstrapProperties bootstrapProperties = new AuthSessionBootstrapProperties();
        bootstrapProperties.setEnabled(true);

        IdentityProviderRegistry registry =
            mock(IdentityProviderRegistry.class);
        when(registry.listReadyProviders()).thenReturn(List.of());
        when(registry.listReadyLoginMethods()).thenReturn(List.of(
            new IdentityProviderLoginMethod(
                "private-sso",
                "Enterprise Password",
                IdentityProviderLoginMethodType.DIRECT_PASSWORD
            ),
            new IdentityProviderLoginMethod(
                "private-sso",
                "Enterprise SSO",
                IdentityProviderLoginMethodType.SESSION_BOOTSTRAP
            )
        ));

        AuthMethodCatalog catalog = new AuthMethodCatalog(
            registry,
            directAuthProperties,
            bootstrapProperties
        );

        assertThat(catalog.listMethods(null))
            .extracting(method -> method.id() + ":" + method.displayName())
            .contains(
                "local-password:Local Account",
                "direct-local:Local Account",
                "direct-private-sso:Enterprise Password",
                "bootstrap-private-sso:Enterprise SSO"
            );
    }

    @Test
    void globalCompatibilityFlagsFilterRegistryCapabilities() {
        IdentityProviderRegistry registry =
            mock(IdentityProviderRegistry.class);
        when(registry.listReadyLoginMethods()).thenReturn(List.of(
            new IdentityProviderLoginMethod(
                "github",
                "GitHub",
                IdentityProviderLoginMethodType.OAUTH_REDIRECT
            ),
            new IdentityProviderLoginMethod(
                "private-sso",
                "Enterprise Password",
                IdentityProviderLoginMethodType.DIRECT_PASSWORD
            ),
            new IdentityProviderLoginMethod(
                "private-sso",
                "Enterprise SSO",
                IdentityProviderLoginMethodType.SESSION_BOOTSTRAP
            )
        ));

        AuthMethodCatalog catalog = new AuthMethodCatalog(
            registry,
            new DirectAuthProperties(),
            new AuthSessionBootstrapProperties()
        );

        assertThat(catalog.listMethods(null))
            .extracting(method -> method.id())
            .containsExactly("local-password", "oauth-github");
    }

}
