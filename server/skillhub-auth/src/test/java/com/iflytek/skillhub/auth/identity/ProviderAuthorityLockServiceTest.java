package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

class ProviderAuthorityLockServiceTest {

    @Test
    void requirePinnedAuthorityFailsClosedOnStickyMismatch() {
        ProviderDescriptor descriptor = descriptor();
        String fingerprint = ProviderAuthorityFingerprint.sha256(
                descriptor.protocol(),
                descriptor.canonicalAuthority());
        ProviderAuthorityStateTransaction transaction =
                mock(ProviderAuthorityStateTransaction.class);
        when(transaction.pin(descriptor, fingerprint)).thenReturn(
                new AuthorityLockEvaluation(
                        IdentityProviderStatus.AUTHORITY_MISMATCH,
                        fingerprint));
        ProviderAuthorityLockService service =
                new ProviderAuthorityLockService(transaction);

        assertThatThrownBy(() -> service.requirePinnedAuthority(descriptor))
                .isInstanceOf(IdentityCoreException.class)
                .extracting("reasonCode")
                .isEqualTo(IdentityFailureCode.PROVIDER_AUTHORITY_MISMATCH);
    }

    private static ProviderDescriptor descriptor() {
        return new ProviderDescriptor(
                "github",
                "oauth2-github",
                "https://github.com",
                "GitHub",
                "github_user_id",
                java.util.Set.of("github_user_id"),
                SubjectCanonicalizer.DECIMAL,
                java.util.List.of("login"),
                java.util.List.of("email"),
                java.util.List.of("avatar_url"),
                EmailAssurance.VERIFIED);
    }
}
