package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.exception.AuthFlowException;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DefaultIdentityProviderAuthorityOperationsTest {

    private TrustedProviderDescriptorSource descriptorSource;
    private ProviderAuthorityLockService authorityLockService;
    private DefaultIdentityProviderAuthorityOperations operations;

    @BeforeEach
    void setUp() {
        descriptorSource = mock(TrustedProviderDescriptorSource.class);
        authorityLockService = mock(ProviderAuthorityLockService.class);
        operations = new DefaultIdentityProviderAuthorityOperations(
                descriptorSource,
                authorityLockService);
    }

    @Test
    void returnsAuditedRecoveryResultForConfiguredAuthority() {
        ProviderDescriptor descriptor = descriptor();
        IdentityProviderAuthorityRecoveryContext context = context();
        when(descriptorSource.enabledDescriptors())
                .thenReturn(List.of(descriptor));
        when(authorityLockService.recoverSameAuthority(
                descriptor,
                context)).thenReturn(new SameAuthorityRecoveryEvaluation(
                        true,
                        new AuthorityLockEvaluation(
                                IdentityProviderStatus.READY,
                                fingerprint())));

        IdentityProviderAuthorityRecoveryResult result =
                operations.recoverSameAuthority("github", context);

        assertThat(result).isEqualTo(
                new IdentityProviderAuthorityRecoveryResult(
                        "github",
                        true,
                        "READY"));
    }

    @Test
    void rejectsRecoveryWhenConfiguredAuthorityStillDiffers() {
        ProviderDescriptor descriptor = descriptor();
        IdentityProviderAuthorityRecoveryContext context = context();
        when(descriptorSource.enabledDescriptors())
                .thenReturn(List.of(descriptor));
        when(authorityLockService.recoverSameAuthority(
                descriptor,
                context)).thenReturn(new SameAuthorityRecoveryEvaluation(
                        false,
                        new AuthorityLockEvaluation(
                                IdentityProviderStatus.AUTHORITY_MISMATCH,
                                "a".repeat(64))));

        assertThatThrownBy(() ->
                operations.recoverSameAuthority("github", context))
                .isInstanceOf(AuthFlowException.class)
                .extracting("status", "messageCode")
                .containsExactly(
                        org.springframework.http.HttpStatus.CONFLICT,
                        "error.auth.provider.authorityRecoveryMismatch");
    }

    @Test
    void rejectsUnknownProviderWithoutTouchingAuthorityState() {
        when(descriptorSource.enabledDescriptors())
                .thenReturn(List.of());

        assertThatThrownBy(() ->
                operations.recoverSameAuthority("unknown", context()))
                .isInstanceOf(AuthFlowException.class)
                .extracting("status", "messageCode")
                .containsExactly(
                        org.springframework.http.HttpStatus.NOT_FOUND,
                        "error.auth.provider.notFound");
    }

    private static IdentityProviderAuthorityRecoveryContext context() {
        return new IdentityProviderAuthorityRecoveryContext(
                "admin",
                "req-123",
                "203.0.113.9",
                "SkillHub Browser");
    }

    private static String fingerprint() {
        return ProviderAuthorityFingerprint.sha256(
                "oauth2-github",
                "https://github.com");
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
