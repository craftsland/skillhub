package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

class ReconciledIdentityProviderCatalogTest {

    private TrustedProviderDescriptorSource descriptorSource;
    private ProviderAuthorityLockService authorityLockService;
    private ReconciledIdentityProviderCatalog catalog;

    @BeforeEach
    void setUp() {
        descriptorSource = mock(TrustedProviderDescriptorSource.class);
        authorityLockService = mock(ProviderAuthorityLockService.class);
        catalog = new ReconciledIdentityProviderCatalog(
                descriptorSource,
                authorityLockService);
    }

    @Test
    void publishesProviderOnlyAfterPinAndPersistedStateReread() {
        ProviderDescriptor github = descriptor("github", "GitHub");
        when(descriptorSource.enabledDescriptors())
                .thenReturn(List.of(github));
        when(authorityLockService.isReady(github)).thenReturn(true);

        catalog.reconcile();

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
        when(descriptorSource.enabledDescriptors())
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
        when(descriptorSource.enabledDescriptors())
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
        when(descriptorSource.enabledDescriptors())
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

    private static ProviderDescriptor descriptor(
            String providerCode,
            String displayName) {
        return new ProviderDescriptor(
                providerCode,
                "oidc",
                "https://" + providerCode + ".example",
                displayName,
                "oidc_sub",
                Set.of("oidc_sub"),
                SubjectCanonicalizer.EXACT,
                List.of("name"),
                List.of("email"),
                List.of("picture"),
                EmailAssurance.VERIFIED);
    }
}
