package com.iflytek.skillhub.auth.merge;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.identity.ExternalIdentityProof;
import com.iflytek.skillhub.auth.identity.ExternalIdentityProofService;
import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
import com.iflytek.skillhub.auth.identity.ProtocolAuthenticationEvidence;
import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;
import com.iflytek.skillhub.auth.identity.ResolvedProviderHandle;
import com.iflytek.skillhub.auth.identity.ResolvedProviderHandleTestFixture;
import com.iflytek.skillhub.auth.identity.SubjectCandidate;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;

class AccountMergeProviderProofServiceTest {

    private static final Instant NOW =
            Instant.parse("2026-07-31T10:00:00Z");
    private static final IdentityLoginContext CONTEXT =
            new IdentityLoginContext(
                    "req-provider-proof",
                    "203.0.113.20",
                    "JUnit");
    private static final ResolvedProviderHandle PROVIDER =
            ResolvedProviderHandleTestFixture.handle("github");

    private ExternalIdentityProofService identityProofService;
    private AccountMergeIntentService intentService;
    private AccountMergeSessionManager sessionManager;
    private AccountMergeProviderProofService service;
    private MockHttpSession session;

    @BeforeEach
    void setUp() {
        identityProofService =
                mock(ExternalIdentityProofService.class);
        intentService =
                mock(AccountMergeIntentService.class);
        sessionManager = new AccountMergeSessionManager(
                Clock.fixed(NOW, ZoneOffset.UTC));
        service = new AccountMergeProviderProofService(
                identityProofService,
                intentService,
                sessionManager,
                mock(AccountMergeMetrics.class));
        session = new MockHttpSession();
        session.setAttribute(
                "platformPrincipal",
                principal("usr_primary"));
    }

    @Test
    void primaryProofMustResolveToTheExistingSessionAccount() {
        when(identityProofService.authenticateExisting(
                PROVIDER,
                result(),
                CONTEXT)).thenReturn(new ExternalIdentityProof(
                        "usr_primary",
                        "github",
                        "oauth2",
                        NOW));

        AccountMergeProviderPrimaryProof completed =
                service.completePrimary(
                        session,
                        PROVIDER,
                        result(),
                        CONTEXT);

        assertThat(completed.principal().userId())
                .isEqualTo("usr_primary");
        assertThat(completed.proof().method())
                .isEqualTo("provider:github");
        assertThat(completed.proof().expiresAt())
                .isEqualTo(NOW.plusSeconds(600));
    }

    @Test
    void providerCannotReauthenticateAnotherAccountAsPrimary() {
        when(identityProofService.authenticateExisting(
                PROVIDER,
                result(),
                CONTEXT)).thenReturn(new ExternalIdentityProof(
                        "usr_secondary",
                        "github",
                        "oauth2",
                        NOW));

        assertThatThrownBy(() ->
                service.completePrimary(
                        session,
                        PROVIDER,
                        result(),
                        CONTEXT))
                .isInstanceOfSatisfying(
                        AccountMergeException.class,
                        exception -> assertThat(
                                exception.getReasonCode())
                                .isEqualTo(
                                        AccountMergeFailureCode
                                                .MERGE_ACCOUNT_NOT_ELIGIBLE));
        assertThatThrownBy(() ->
                sessionManager.startIntent(
                        session,
                        UUID.randomUUID(),
                        CONTEXT))
                .isInstanceOfSatisfying(
                        AccountMergeException.class,
                        exception -> assertThat(
                                exception.getReasonCode())
                                .isEqualTo(
                                        AccountMergeFailureCode
                                                .MERGE_REAUTH_REQUIRED));
    }

    @Test
    void secondaryProofComesOnlyFromExistingIdentityResolution() {
        UUID intentId = UUID.randomUUID();
        AccountMergeActor actor = new AccountMergeActor(
                "usr_primary",
                "local",
                "high-entropy-nonce",
                "local-password",
                NOW,
                CONTEXT);
        AccountMergeIntent expected = new AccountMergeIntent(
                intentId,
                AccountMergeIntentStatus.READY_FOR_PREVIEW,
                NOW.plusSeconds(600));
        when(identityProofService.authenticateExisting(
                PROVIDER,
                result(),
                CONTEXT)).thenReturn(new ExternalIdentityProof(
                        "usr_secondary",
                        "github",
                        "oauth2",
                        NOW));
        when(intentService.recordSecondaryProof(
                actor,
                intentId,
                "usr_secondary",
                "provider:github")).thenReturn(expected);

        assertThat(service.completeSecondary(
                actor,
                intentId,
                PROVIDER,
                result(),
                CONTEXT)).isSameAs(expected);
        verify(intentService).recordSecondaryProof(
                actor,
                intentId,
                "usr_secondary",
                "provider:github");
    }

    private static ProviderAuthenticationResult result() {
        return new ProviderAuthenticationResult(
                new SubjectCandidate(
                        "github_user_id",
                        "123"),
                List.of(),
                Map.of(),
                new ProtocolAuthenticationEvidence(
                        "oauth2-github",
                        NOW,
                        Set.of("oauth2_authorization_code")));
    }

    private static PlatformPrincipal principal(String userId) {
        return new PlatformPrincipal(
                userId,
                "User",
                "user@example.com",
                null,
                "github",
                Set.of("USER"));
    }
}
