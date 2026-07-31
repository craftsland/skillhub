package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.provider.BrowserAuthenticationAdapter;
import com.iflytek.skillhub.auth.provider.BrowserAuthenticationMethod;
import com.iflytek.skillhub.auth.provider.CredentialAuthenticationAdapter;
import com.iflytek.skillhub.auth.provider.CredentialAuthenticationRequest;
import com.iflytek.skillhub.auth.provider.PassiveAuthenticationAdapter;
import com.iflytek.skillhub.auth.provider.PassiveAuthenticationRequest;
import com.iflytek.skillhub.auth.provider.ProviderInstanceDefinition;
import com.iflytek.skillhub.auth.provider.SubjectNormalization;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

class ReconciledIdentityProviderCatalogTest {

    private ConfiguredProviderDescriptorSource descriptorSource;
    private ProviderAuthorityLockService authorityLockService;
    private IdentityBindingPreflightService bindingPreflightService;
    private ReconciledIdentityProviderCatalog catalog;

    @BeforeEach
    void setUp() {
        descriptorSource = mock(
                ConfiguredProviderDescriptorSource.class);
        authorityLockService = mock(ProviderAuthorityLockService.class);
        bindingPreflightService = mock(
                IdentityBindingPreflightService.class);
        when(bindingPreflightService
                .findProvidersWithoutTrustedDescriptor(anyList()))
                .thenReturn(List.of());
        catalog = new ReconciledIdentityProviderCatalog(
                descriptorSource,
                authorityLockService,
                bindingPreflightService,
                new IdentityProviderPolicyProperties(),
                List.of(),
                List.of(),
                List.of());
    }

    @Test
    void publishesProviderOnlyAfterPinAndPersistedStateReread() {
        ProviderDescriptor github = descriptor("github", "GitHub");
        when(descriptorSource.configuredDescriptors())
                .thenReturn(List.of(github));
        when(authorityLockService.isReady(github)).thenReturn(true);

        catalog.reconcile();

        verify(bindingPreflightService)
                .findProvidersWithoutTrustedDescriptor(
                        List.of(github));

        assertThat(catalog.listReadyProviders())
                .containsExactly(new IdentityProviderLoginMethod(
                        "github",
                        "GitHub"));
        InOrder order = inOrder(authorityLockService);
        order.verify(authorityLockService, times(2))
                .requirePinnedAuthority(github);
        order.verify(authorityLockService).isReady(github);
    }

    @Test
    void hidesProvidersWhosePinOrPersistedStateCheckFails() {
        ProviderDescriptor github = descriptor("github", "GitHub");
        ProviderDescriptor gitlab = descriptor("gitlab", "GitLab");
        when(descriptorSource.configuredDescriptors())
                .thenReturn(List.of(github, gitlab));
        doThrow(new IdentityCoreException(
                IdentityFailureCode.PROVIDER_AUTHORITY_MISMATCH))
                .when(authorityLockService)
                .requirePinnedAuthority(github);
        when(authorityLockService.isReady(github)).thenReturn(false);
        when(authorityLockService.isReady(gitlab)).thenReturn(false);

        catalog.reconcile();

        assertThat(catalog.listReadyProviders()).isEmpty();
    }

    @Test
    void persistedStateReadFailureCannotExposePreviouslyReadyProvider() {
        ProviderDescriptor github = descriptor("github", "GitHub");
        when(descriptorSource.configuredDescriptors())
                .thenReturn(List.of(github));
        when(authorityLockService.isReady(github)).thenReturn(true);
        catalog.reconcile();
        assertThat(catalog.listReadyProviders()).hasSize(1);

        doThrow(new IllegalStateException("database unavailable"))
                .when(authorityLockService)
                .requirePinnedAuthority(github);
        when(authorityLockService.isReady(github))
                .thenThrow(new IllegalStateException(
                        "database unavailable"));

        catalog.reconcile();

        assertThat(catalog.listReadyProviders()).isEmpty();
    }

    @Test
    void reflectsSameAuthorityRecoveryWithoutApplicationRestart() {
        ProviderDescriptor github = descriptor("github", "GitHub");
        when(descriptorSource.configuredDescriptors())
                .thenReturn(List.of(github));
        when(authorityLockService.isReady(github))
                .thenReturn(false, true);
        catalog.reconcile();

        assertThat(catalog.listReadyProviders()).isEmpty();
        assertThat(catalog.listReadyProviders())
                .containsExactly(new IdentityProviderLoginMethod(
                        "github",
                        "GitHub"));
    }

    @Test
    void projectsCredentialAndPassiveCapabilitiesFromOneProvider() {
        CredentialAuthenticationAdapter credential =
                new CredentialAuthenticationAdapter() {
                    @Override
                    public ProviderInstanceDefinition provider() {
                        return definition(
                                "private-sso",
                                "https://sso.example");
                    }

                    @Override
                    public ProviderAuthenticationResult authenticate(
                            CredentialAuthenticationRequest request) {
                        throw new UnsupportedOperationException(
                                "not called");
                    }
                };
        PassiveAuthenticationAdapter passive =
                new PassiveAuthenticationAdapter() {
                    @Override
                    public ProviderInstanceDefinition provider() {
                        return definition(
                                "private-sso",
                                "https://sso.example");
                    }

                    @Override
                    public Optional<ProviderAuthenticationResult> authenticate(
                            PassiveAuthenticationRequest request) {
                        throw new UnsupportedOperationException(
                                "not called");
                    }
                };
        when(descriptorSource.configuredDescriptors())
                .thenReturn(List.of());
        when(authorityLockService.isReady(any()))
                .thenReturn(true);
        catalog = new ReconciledIdentityProviderCatalog(
                descriptorSource,
                authorityLockService,
                bindingPreflightService,
                new IdentityProviderPolicyProperties(),
                List.of(),
                List.of(credential),
                List.of(passive));

        catalog.reconcile();

        assertThat(catalog.listReadyLoginMethods())
                .containsExactly(
                        new IdentityProviderLoginMethod(
                                "private-sso",
                                "Private SSO",
                                IdentityProviderLoginMethodType
                                        .DIRECT_PASSWORD),
                        new IdentityProviderLoginMethod(
                                "private-sso",
                                "Private SSO",
                                IdentityProviderLoginMethodType
                                        .SESSION_BOOTSTRAP));
        assertThat(catalog.requireCredentialRoute("private-sso")
                .adapter()).isSameAs(credential);
        assertThat(catalog.requirePassiveRoute("private-sso")
                .adapter()).isSameAs(passive);
    }

    @Test
    void disabledAdapterIsNotRoutableOrInvoked() {
        CredentialAuthenticationAdapter adapter =
                mock(CredentialAuthenticationAdapter.class);
        ProviderInstanceDefinition disabled = new ProviderInstanceDefinition(
                "disabled",
                "ldap",
                "ldap://directory.example",
                "Disabled Directory",
                "ldap_entry_uuid",
                "ldap_entry_uuid",
                Map.of(
                        "ldap_entry_uuid",
                        SubjectNormalization.EXACT),
                List.of("displayName"),
                List.of("mail"),
                List.of(),
                EmailAssurance.VERIFIED,
                false);
        when(adapter.provider()).thenReturn(disabled);
        when(descriptorSource.configuredDescriptors())
                .thenReturn(List.of());
        catalog = new ReconciledIdentityProviderCatalog(
                descriptorSource,
                authorityLockService,
                bindingPreflightService,
                new IdentityProviderPolicyProperties(),
                List.of(),
                List.of(adapter),
                List.of());

        catalog.reconcile();

        assertThat(catalog.listReadyLoginMethods()).isEmpty();
        assertThatThrownBy(
                () -> catalog.requireCredentialRoute("disabled"))
                .isInstanceOf(IdentityCoreException.class)
                .extracting("reasonCode")
                .isEqualTo(IdentityFailureCode.PROVIDER_DISABLED);
        verify(adapter, never()).authenticate(any());
    }

    @Test
    void conflictingTrustedDefinitionsFailClosed() {
        CredentialAuthenticationAdapter credential =
                mock(CredentialAuthenticationAdapter.class);
        PassiveAuthenticationAdapter passive =
                mock(PassiveAuthenticationAdapter.class);
        when(credential.provider()).thenReturn(definition(
                "private-sso",
                "https://one.example"));
        when(passive.provider()).thenReturn(definition(
                "private-sso",
                "https://two.example"));
        when(descriptorSource.configuredDescriptors())
                .thenReturn(List.of());
        catalog = new ReconciledIdentityProviderCatalog(
                descriptorSource,
                authorityLockService,
                bindingPreflightService,
                new IdentityProviderPolicyProperties(),
                List.of(),
                List.of(credential),
                List.of(passive));

        catalog.reconcile();

        assertThat(catalog.listReadyLoginMethods()).isEmpty();
        assertThat(catalog.enabledDescriptors()).isEmpty();
        verify(credential, never()).authenticate(any());
        verify(passive, never()).authenticate(any());
    }

    @Test
    void misconfiguredAdapterCannotBecomeRoutable() {
        CredentialAuthenticationAdapter adapter =
                mock(CredentialAuthenticationAdapter.class);
        when(adapter.provider()).thenThrow(
                new IllegalArgumentException(
                        "invalid trusted configuration"));
        when(descriptorSource.configuredDescriptors())
                .thenReturn(List.of());
        catalog = new ReconciledIdentityProviderCatalog(
                descriptorSource,
                authorityLockService,
                bindingPreflightService,
                new IdentityProviderPolicyProperties(),
                List.of(),
                List.of(adapter),
                List.of());

        catalog.reconcile();

        assertThat(catalog.listReadyLoginMethods()).isEmpty();
        verify(adapter, never()).authenticate(any());
    }

    @Test
    void registersAndRoutesReadyCasBrowserAdapterByExchangeType() {
        BrowserAuthenticationAdapter<String> adapter =
                new BrowserAuthenticationAdapter<>() {
                    @Override
                    public ProviderInstanceDefinition provider() {
                        return new ProviderInstanceDefinition(
                                "cas-main",
                                "cas",
                                "corp-cas",
                                "Corporate CAS",
                                "cas_principal",
                                "cas_principal",
                                Map.of(
                                        "cas_principal",
                                        SubjectNormalization.EXACT),
                                List.of("display_name"),
                                List.of("email"),
                                List.of(),
                                EmailAssurance.PROVIDER_ASSERTED);
                    }

                    @Override
                    public Class<String> exchangeType() {
                        return String.class;
                    }

                    @Override
                    public BrowserAuthenticationMethod loginMethod() {
                        return BrowserAuthenticationMethod.CAS_REDIRECT;
                    }

                    @Override
                    public ProviderAuthenticationResult authenticate(
                            String exchange) {
                        throw new UnsupportedOperationException(
                                "not called");
                    }
                };
        when(descriptorSource.configuredDescriptors())
                .thenReturn(List.of());
        when(authorityLockService.isReady(any()))
                .thenReturn(true);
        catalog = new ReconciledIdentityProviderCatalog(
                descriptorSource,
                authorityLockService,
                bindingPreflightService,
                new IdentityProviderPolicyProperties(),
                List.of(adapter),
                List.of(),
                List.of());

        catalog.reconcile();

        assertThat(catalog.listReadyLoginMethods())
                .containsExactly(new IdentityProviderLoginMethod(
                        "cas-main",
                        "Corporate CAS",
                        IdentityProviderLoginMethodType.CAS_REDIRECT));
        assertThat(catalog.requireBrowserRoute(
                "cas-main",
                String.class).adapter()).isSameAs(adapter);
        assertThatThrownBy(() -> catalog.requireBrowserRoute(
                "cas-main",
                Integer.class))
                .isInstanceOf(IdentityCoreException.class)
                .extracting("reasonCode")
                .isEqualTo(IdentityFailureCode.PROVIDER_DISABLED);
    }

    private static ProviderDescriptor descriptor(
            String providerCode,
            String displayName) {
        return new ProviderDescriptor(
                providerCode,
                "oidc",
                "https://" + providerCode + ".example",
                displayName,
                "oidc_sub",
                "oidc_sub",
                java.util.Map.of(
                        "oidc_sub",
                        SubjectCanonicalizer.EXACT),
                List.of("name"),
                List.of("email"),
                List.of("picture"),
                EmailAssurance.VERIFIED);
    }

    private static ProviderInstanceDefinition definition(
            String providerCode,
            String authority) {
        return new ProviderInstanceDefinition(
                providerCode,
                "private-sso",
                authority,
                "Private SSO",
                "private_subject",
                "private_subject",
                Map.of(
                        "private_subject",
                        SubjectNormalization.EXACT),
                List.of("display_name"),
                List.of("email"),
                List.of("avatar_url"),
                EmailAssurance.VERIFIED);
    }
}
