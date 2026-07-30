package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.springframework.dao.DataIntegrityViolationException;

class DefaultExternalIdentityLoginServiceTest {

    private final ProviderDescriptor descriptor = descriptor();
    private TrustedProviderDescriptorSource descriptorSource;
    private ProviderAuthorityLockService authorityLockService;
    private IdentityResolutionTransaction resolutionTransaction;
    private IdentityLoginMetrics metrics;
    private DefaultExternalIdentityLoginService service;

    @BeforeEach
    void setUp() {
        descriptorSource =
                mock(TrustedProviderDescriptorSource.class);
        authorityLockService =
                mock(ProviderAuthorityLockService.class);
        resolutionTransaction =
                mock(IdentityResolutionTransaction.class);
        metrics = mock(IdentityLoginMetrics.class);
        service = new DefaultExternalIdentityLoginService(
                descriptorSource,
                authorityLockService,
                new IdentityAssertionFactory(),
                resolutionTransaction,
                metrics);
    }

    @Test
    void resolvesTrustedProviderBeforeAuthorityAssertionAndTransaction() {
        ResolvedProviderHandle handle =
                new DefaultResolvedProviderHandle("github");
        ProviderAuthenticationResult result = result();
        IdentityLoginContext context = IdentityLoginContext.empty();
        IdentityLoginOutcome expected = authenticated();
        when(descriptorSource.require(handle)).thenReturn(descriptor);
        when(resolutionTransaction.resolve(
                any(IdentityAssertion.class),
                org.mockito.ArgumentMatchers.eq(descriptor),
                org.mockito.ArgumentMatchers.eq(context)))
                .thenReturn(expected);

        IdentityLoginOutcome outcome =
                service.authenticate(handle, result, context);

        assertThat(outcome).isSameAs(expected);
        InOrder order = inOrder(
                descriptorSource,
                authorityLockService,
                resolutionTransaction,
                metrics);
        order.verify(descriptorSource).require(handle);
        order.verify(authorityLockService)
                .requirePinnedAuthority(descriptor);
        order.verify(resolutionTransaction).resolve(
                any(IdentityAssertion.class),
                org.mockito.ArgumentMatchers.eq(descriptor),
                org.mockito.ArgumentMatchers.eq(context));
        order.verify(metrics).recordOutcome("github", expected);
    }

    @Test
    void recordsPendingOutcomeWithoutReinterpretingIt() {
        ResolvedProviderHandle handle =
                new DefaultResolvedProviderHandle("github");
        IdentityLoginOutcome pending =
                new IdentityLoginOutcome.PendingApproval(
                        "ACCOUNT_PENDING");
        when(descriptorSource.require(handle)).thenReturn(descriptor);
        when(resolutionTransaction.resolve(
                any(IdentityAssertion.class),
                org.mockito.ArgumentMatchers.eq(descriptor),
                any(IdentityLoginContext.class)))
                .thenReturn(pending);

        IdentityLoginOutcome outcome = service.authenticate(
                handle,
                result(),
                IdentityLoginContext.empty());

        assertThat(outcome).isSameAs(pending);
        verify(metrics).recordOutcome("github", pending);
    }

    @Test
    void retriesConcurrentFirstLoginInANewResolutionTransaction() {
        ResolvedProviderHandle handle =
                new DefaultResolvedProviderHandle("github");
        IdentityLoginOutcome expected = authenticated();
        when(descriptorSource.require(handle))
                .thenReturn(descriptor);
        when(resolutionTransaction.resolve(
                any(IdentityAssertion.class),
                org.mockito.ArgumentMatchers.eq(descriptor),
                any(IdentityLoginContext.class)))
                .thenThrow(uniqueViolation())
                .thenReturn(expected);

        IdentityLoginOutcome outcome = service.authenticate(
                handle,
                result(),
                IdentityLoginContext.empty());

        assertThat(outcome).isSameAs(expected);
        verify(resolutionTransaction,
                org.mockito.Mockito.times(2)).resolve(
                        any(IdentityAssertion.class),
                        org.mockito.ArgumentMatchers.eq(descriptor),
                        any(IdentityLoginContext.class));
        verify(metrics).recordOutcome("github", expected);
    }

    @Test
    void repeatedUniqueConflictFailsClosedAndRecordsReason() {
        ResolvedProviderHandle handle =
                new DefaultResolvedProviderHandle("github");
        when(descriptorSource.require(handle))
                .thenReturn(descriptor);
        when(resolutionTransaction.resolve(
                any(IdentityAssertion.class),
                org.mockito.ArgumentMatchers.eq(descriptor),
                any(IdentityLoginContext.class)))
                .thenThrow(uniqueViolation(), uniqueViolation());

        assertThatThrownBy(() -> service.authenticate(
                handle,
                result(),
                IdentityLoginContext.empty()))
                .isInstanceOf(IdentityCoreException.class)
                .extracting("reasonCode")
                .isEqualTo(
                        IdentityFailureCode
                                .IDENTITY_IDENTIFIER_CONFLICT);
        verify(metrics).recordFailure(
                "github",
                IdentityFailureCode.IDENTITY_IDENTIFIER_CONFLICT);
    }

    @Test
    void nonUniqueIntegrityFailureIsNotRetriedOrMisclassified() {
        ResolvedProviderHandle handle =
                new DefaultResolvedProviderHandle("github");
        DataIntegrityViolationException checkViolation =
                new DataIntegrityViolationException(
                        "check violation",
                        new SQLException(
                                "check violation",
                                "23514"));
        when(descriptorSource.require(handle))
                .thenReturn(descriptor);
        when(resolutionTransaction.resolve(
                any(IdentityAssertion.class),
                org.mockito.ArgumentMatchers.eq(descriptor),
                any(IdentityLoginContext.class)))
                .thenThrow(checkViolation);

        assertThatThrownBy(() -> service.authenticate(
                handle,
                result(),
                IdentityLoginContext.empty()))
                .isSameAs(checkViolation);
        verify(resolutionTransaction).resolve(
                any(IdentityAssertion.class),
                org.mockito.ArgumentMatchers.eq(descriptor),
                any(IdentityLoginContext.class));
        verify(metrics).recordSystemError("github");
    }

    private static IdentityLoginOutcome authenticated() {
        PlatformPrincipal principal = new PlatformPrincipal(
                "usr_1",
                "alice",
                "alice@example.com",
                null,
                "github",
                Set.of("USER"));
        return new IdentityLoginOutcome.Authenticated(
                principal,
                false,
                false);
    }

    private static DataIntegrityViolationException uniqueViolation() {
        return new DataIntegrityViolationException(
                "unique violation",
                new SQLException(
                        "unique violation",
                        "23505"));
    }

    private static ProviderAuthenticationResult result() {
        return new ProviderAuthenticationResult(
                new SubjectCandidate(
                        "github_user_id",
                        "123456"),
                List.of(),
                Map.of(
                        "login",
                        List.of(new ProviderAttributeValue(
                                "alice",
                                ProviderAttributeTrust.ASSERTED)),
                        "email",
                        List.of(new ProviderAttributeValue(
                                "alice@example.com",
                                ProviderAttributeTrust.VERIFIED))),
                new ProtocolAuthenticationEvidence(
                        "oauth2-github",
                        Instant.parse("2026-07-30T08:00:00Z"),
                        Set.of("oauth2_authorization_code")));
    }

    private static ProviderDescriptor descriptor() {
        return new ProviderDescriptor(
                "github",
                "oauth2-github",
                "https://github.com",
                "GitHub",
                "github_user_id",
                "github_user_id",
                Map.of(
                        "github_user_id",
                        SubjectCanonicalizer.DECIMAL),
                List.of("login"),
                List.of("email"),
                List.of("avatar_url"),
                EmailAssurance.VERIFIED);
    }
}
