package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.policy.AccessDecision;
import com.iflytek.skillhub.auth.policy.AccessPolicy;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.domain.user.UserStatus;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.mockito.ArgumentCaptor;

class DefaultExternalIdentityLoginServiceTest {

    private final ProviderDescriptor descriptor = descriptor();
    private TrustedProviderDescriptorSource descriptorSource;
    private ProviderAuthorityLockService authorityLockService;
    private AccessPolicy accessPolicy;
    private IdentityResolutionTransaction resolutionTransaction;
    private DefaultExternalIdentityLoginService service;

    @BeforeEach
    void setUp() {
        descriptorSource = mock(TrustedProviderDescriptorSource.class);
        authorityLockService = mock(ProviderAuthorityLockService.class);
        accessPolicy = mock(AccessPolicy.class);
        resolutionTransaction = mock(IdentityResolutionTransaction.class);
        service = new DefaultExternalIdentityLoginService(
                descriptorSource,
                authorityLockService,
                new IdentityAssertionFactory(),
                accessPolicy,
                resolutionTransaction);
    }

    @Test
    void resolvesTrustedProviderBeforeAuthorityAssertionPolicyAndTransaction() {
        ResolvedProviderHandle handle =
                new DefaultResolvedProviderHandle("github");
        ProviderAuthenticationResult result = result();
        IdentityLoginContext context = IdentityLoginContext.empty();
        PlatformPrincipal principal = new PlatformPrincipal(
                "usr_1",
                "alice",
                "alice@example.com",
                null,
                "github",
                Set.of("USER"));
        IdentityLoginOutcome expected =
                new IdentityLoginOutcome.Authenticated(
                        principal,
                        false,
                        false);
        when(descriptorSource.require(handle)).thenReturn(descriptor);
        when(accessPolicy.evaluate(any())).thenReturn(AccessDecision.ALLOW);
        when(resolutionTransaction.resolve(
                any(IdentityAssertion.class),
                org.mockito.ArgumentMatchers.eq(UserStatus.ACTIVE)))
                .thenReturn(expected);

        IdentityLoginOutcome outcome =
                service.authenticate(handle, result, context);

        assertThat(outcome).isSameAs(expected);
        ArgumentCaptor<com.iflytek.skillhub.auth.policy.IdentityAccessContext>
                accessContext = ArgumentCaptor.forClass(
                        com.iflytek.skillhub.auth.policy.IdentityAccessContext.class);
        verify(accessPolicy).evaluate(accessContext.capture());
        assertThat(accessContext.getValue().requestContext())
                .isSameAs(context);
        InOrder order = inOrder(
                descriptorSource,
                authorityLockService,
                accessPolicy,
                resolutionTransaction);
        order.verify(descriptorSource).require(handle);
        order.verify(authorityLockService).requirePinnedAuthority(descriptor);
        order.verify(accessPolicy).evaluate(any());
        order.verify(resolutionTransaction).resolve(
                any(IdentityAssertion.class),
                org.mockito.ArgumentMatchers.eq(UserStatus.ACTIVE));
    }

    @Test
    void pendingPolicyUsesCompatibilityPendingProvisioningMode() {
        ResolvedProviderHandle handle =
                new DefaultResolvedProviderHandle("github");
        when(descriptorSource.require(handle)).thenReturn(descriptor);
        when(accessPolicy.evaluate(any()))
                .thenReturn(AccessDecision.PENDING_APPROVAL);
        IdentityLoginOutcome pending =
                new IdentityLoginOutcome.PendingApproval("ACCOUNT_PENDING");
        when(resolutionTransaction.resolve(
                any(IdentityAssertion.class),
                org.mockito.ArgumentMatchers.eq(UserStatus.PENDING)))
                .thenReturn(pending);

        IdentityLoginOutcome outcome =
                service.authenticate(
                        handle,
                        result(),
                        IdentityLoginContext.empty());

        assertThat(outcome).isSameAs(pending);
    }

    @Test
    void deniedPolicyNeverReachesProvisioningTransaction() {
        ResolvedProviderHandle handle =
                new DefaultResolvedProviderHandle("github");
        when(descriptorSource.require(handle)).thenReturn(descriptor);
        when(accessPolicy.evaluate(any())).thenReturn(AccessDecision.DENY);

        assertThatThrownBy(() -> service.authenticate(
                handle,
                result(),
                IdentityLoginContext.empty()))
                .isInstanceOf(IdentityCoreException.class)
                .extracting("reasonCode")
                .isEqualTo(IdentityFailureCode.ACCESS_DENIED);

        verify(resolutionTransaction, never()).resolve(any(), any());
    }

    private static ProviderAuthenticationResult result() {
        return new ProviderAuthenticationResult(
                new SubjectCandidate("github_user_id", "123456"),
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
                Set.of("github_user_id"),
                SubjectCanonicalizer.DECIMAL,
                List.of("login"),
                List.of("email"),
                List.of("avatar_url"),
                EmailAssurance.VERIFIED);
    }
}
