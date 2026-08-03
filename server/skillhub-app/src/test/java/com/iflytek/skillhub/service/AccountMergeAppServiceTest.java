package com.iflytek.skillhub.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.exception.AuthFlowException;
import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
import com.iflytek.skillhub.auth.identity.IdentityLinkAccountState;
import com.iflytek.skillhub.auth.identity.IdentityLinkBindingView;
import com.iflytek.skillhub.auth.identity.IdentityLinkIntentService;
import com.iflytek.skillhub.auth.identity.IdentityLinkSessionManager;
import com.iflytek.skillhub.auth.identity.IdentityProviderRegistry;
import com.iflytek.skillhub.auth.identity.IdentityProviderLoginMethod;
import com.iflytek.skillhub.auth.identity.IdentityProviderLoginMethodType;
import com.iflytek.skillhub.auth.local.LocalAuthService;
import com.iflytek.skillhub.auth.merge.AccountMergeException;
import com.iflytek.skillhub.auth.merge.AccountMergeFailureCode;
import com.iflytek.skillhub.auth.merge.AccountMergeIntent;
import com.iflytek.skillhub.auth.merge.AccountMergeIntentService;
import com.iflytek.skillhub.auth.merge.AccountMergeIntentStatus;
import com.iflytek.skillhub.auth.merge.AccountMergeMetrics;
import com.iflytek.skillhub.auth.merge.AccountMergeProviderProofService;
import com.iflytek.skillhub.auth.merge.AccountMergeSessionManager;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.dto.AccountMergeIntentResponse;
import java.util.List;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.context.support.StaticMessageSource;

class AccountMergeAppServiceTest {

    private static final Clock CLOCK = Clock.fixed(
            Instant.parse("2026-07-31T09:00:00Z"),
            ZoneOffset.UTC);
    private static final IdentityLoginContext CONTEXT =
            new IdentityLoginContext(
                    "req-merge-1",
                    "203.0.113.10",
                    "Browser");

    private AccountMergeIntentService intentService;
    private LocalAuthService localAuthService;
    private IdentityProviderRegistry providerRegistry;
    private IdentityLinkIntentService identityLinkIntentService;
    private IdentityLinkSessionManager identityLinkSessionManager;
    private AccountMergeSessionManager accountMergeSessionManager;
    private AccountMergeMetrics metrics;
    private AccountMergeAppService service;
    private MockHttpSession session;
    private PlatformPrincipal principal;

    @BeforeEach
    void setUp() {
        intentService = mock(AccountMergeIntentService.class);
        localAuthService = mock(LocalAuthService.class);
        providerRegistry = mock(IdentityProviderRegistry.class);
        identityLinkIntentService =
                mock(IdentityLinkIntentService.class);
        identityLinkSessionManager =
                mock(IdentityLinkSessionManager.class);
        accountMergeSessionManager =
                new AccountMergeSessionManager(CLOCK);
        metrics = mock(AccountMergeMetrics.class);
        StaticMessageSource messageSource =
                new StaticMessageSource();
        messageSource.addMessage(
                "auth.accountMerge.method.localPassword",
                java.util.Locale.ENGLISH,
                "Local password");
        service = new AccountMergeAppService(
                intentService,
                localAuthService,
                accountMergeSessionManager,
                mock(AccountMergeProviderProofService.class),
                providerRegistry,
                mock(ProviderLoginAppService.class),
                identityLinkIntentService,
                identityLinkSessionManager,
                metrics,
                messageSource);
        principal = new PlatformPrincipal(
                "usr_primary",
                "Primary",
                "primary@example.com",
                null,
                "local",
                Set.of("USER"));
        session = new MockHttpSession();
        session.setAttribute("platformPrincipal", principal);
    }

    @Test
    void intentCannotBeCreatedBeforeFreshReauthentication() {
        assertThatThrownBy(() ->
                service.createIntent(session, CONTEXT))
                .isInstanceOfSatisfying(
                        AccountMergeException.class,
                        exception -> assertThat(
                                exception.getReasonCode())
                                .isEqualTo(
                                        AccountMergeFailureCode
                                                .MERGE_REAUTH_REQUIRED));
    }

    @Test
    void localReauthenticationProofIsConsumedByIntentCreation() {
        when(localAuthService.reauthenticate(
                "usr_primary",
                "correct-password")).thenReturn(principal);
        when(intentService.createIntent(
                any(),
                any())).thenAnswer(invocation -> {
                    UUID intentId = invocation.getArgument(1);
                    return new AccountMergeIntent(
                            intentId,
                            AccountMergeIntentStatus
                                    .PENDING_SECONDARY_PROOF,
                            Instant.parse(
                                    "2026-07-31T09:10:00Z"));
                });

        service.reauthenticatePrimaryLocal(
                "correct-password",
                session);
        AccountMergeIntentResponse response =
                service.createIntent(session, CONTEXT);

        assertThat(response.status()).isEqualTo(
                AccountMergeIntentStatus
                        .PENDING_SECONDARY_PROOF);
        verify(localAuthService).reauthenticate(
                "usr_primary",
                "correct-password");
        verify(intentService).createIntent(any(), any());

        assertThatThrownBy(() ->
                service.createIntent(session, CONTEXT))
                .isInstanceOfSatisfying(
                        AccountMergeException.class,
                        exception -> assertThat(
                                exception.getReasonCode())
                                .isEqualTo(
                                        AccountMergeFailureCode
                                                .MERGE_REAUTH_REQUIRED));
    }

    @Test
    void secondaryLocalAuthenticationDoesNotReplacePrimarySession() {
        PlatformPrincipal secondary = new PlatformPrincipal(
                "usr_secondary",
                "Secondary",
                "secondary@example.com",
                null,
                "local",
                Set.of("USER"));
        when(localAuthService.reauthenticate(
                "usr_primary",
                "primary-password")).thenReturn(principal);
        when(localAuthService.login(
                "secondary-user",
                "secondary-password")).thenReturn(secondary);
        when(intentService.createIntent(
                any(),
                any())).thenAnswer(invocation ->
                        intent(
                                invocation.getArgument(1),
                                AccountMergeIntentStatus
                                        .PENDING_SECONDARY_PROOF));
        when(intentService.recordSecondaryProof(
                any(),
                any(),
                any(),
                any())).thenAnswer(invocation ->
                        intent(
                                invocation.getArgument(1),
                                AccountMergeIntentStatus
                                        .READY_FOR_PREVIEW));

        service.reauthenticatePrimaryLocal(
                "primary-password",
                session);
        UUID intentId =
                service.createIntent(session, CONTEXT).id();
        AccountMergeIntentResponse response =
                service.authenticateSecondaryLocal(
                        intentId,
                        "secondary-user",
                        "secondary-password",
                        session,
                        CONTEXT);

        assertThat(response.status()).isEqualTo(
                AccountMergeIntentStatus.READY_FOR_PREVIEW);
        assertThat(session.getAttribute("platformPrincipal"))
                .isSameAs(principal);
        verify(intentService).recordSecondaryProof(
                any(),
                org.mockito.ArgumentMatchers.eq(intentId),
                org.mockito.ArgumentMatchers.eq("usr_secondary"),
                org.mockito.ArgumentMatchers.eq("local-password"));
    }

    @Test
    void invalidPasswordDoesNotLeaveAUsablePrimaryProof() {
        when(localAuthService.reauthenticate(
                "usr_primary",
                "wrong-password")).thenThrow(
                        new AuthFlowException(
                                HttpStatus.UNAUTHORIZED,
                                "error.auth.local.invalidCredentials"));

        assertThatThrownBy(() ->
                service.reauthenticatePrimaryLocal(
                        "wrong-password",
                        session))
                .isInstanceOfSatisfying(
                        AccountMergeException.class,
                        exception -> assertThat(
                                exception.getReasonCode())
                                .isEqualTo(
                                        AccountMergeFailureCode
                                                .MERGE_REAUTH_REQUIRED));
        assertThatThrownBy(() ->
                service.createIntent(session, CONTEXT))
                .isInstanceOf(AccountMergeException.class);
        verify(metrics).record(
                "proof",
                "primary_local_failure");
    }

    @Test
    void capabilitiesExposeOnlyUsableFreshAuthenticationMethods() {
        when(intentService.isAvailable()).thenReturn(true);
        when(identityLinkIntentService.accountState(
                "usr_primary")).thenReturn(
                        new IdentityLinkAccountState(
                                true,
                                List.of(
                                        new IdentityLinkBindingView(
                                                1L,
                                                "github",
                                                "GitHub",
                                                Set.of(
                                                        IdentityProviderLoginMethodType
                                                                .OAUTH_REDIRECT),
                                                true,
                                                true),
                                        new IdentityLinkBindingView(
                                                2L,
                                                "disabled",
                                                "Disabled",
                                                Set.of(),
                                                false,
                                                true)),
                                List.of()));
        when(providerRegistry.listReadyLoginMethods())
                .thenReturn(List.of(
                        new IdentityProviderLoginMethod(
                                "cas-main",
                                "Corporate CAS",
                                IdentityProviderLoginMethodType
                                        .CAS_REDIRECT),
                        new IdentityProviderLoginMethod(
                                "bootstrap",
                                "Bootstrap",
                                IdentityProviderLoginMethodType
                                        .SESSION_BOOTSTRAP)));

        var capabilities = service.capabilities(session);

        assertThat(capabilities.enabled()).isTrue();
        assertThat(capabilities.primaryMethods())
                .extracting("providerCode", "methodType")
                .containsExactly(
                        org.assertj.core.groups.Tuple.tuple(
                                "github",
                                "OAUTH_REDIRECT"),
                        org.assertj.core.groups.Tuple.tuple(
                                "local",
                                "LOCAL_PASSWORD"));
        assertThat(capabilities.secondaryMethods())
                .extracting("providerCode", "methodType")
                .containsExactly(
                        org.assertj.core.groups.Tuple.tuple(
                                "cas-main",
                                "CAS_REDIRECT"),
                        org.assertj.core.groups.Tuple.tuple(
                                "local",
                                "LOCAL_PASSWORD"));
    }

    @Test
    void primaryBrowserFlowUsesOnlyALinkedProviderAndClearsIdentityLinkState() {
        when(identityLinkIntentService.accountState(
                "usr_primary")).thenReturn(
                        new IdentityLinkAccountState(
                                false,
                                List.of(
                                        new IdentityLinkBindingView(
                                                1L,
                                                "github",
                                                "GitHub",
                                                Set.of(
                                                        IdentityProviderLoginMethodType
                                                                .OAUTH_REDIRECT),
                                                true,
                                                true)),
                                List.of()));

        var started = service.reauthenticatePrimaryBrowser(
                "github",
                session);

        assertThat(started.actionUrl())
                .startsWith(
                        "/oauth2/authorization/github");
        verify(identityLinkSessionManager)
                .clearBrowserFlow(session);
    }

    private AccountMergeIntent intent(
            UUID intentId,
            AccountMergeIntentStatus status) {
        return new AccountMergeIntent(
                intentId,
                status,
                Instant.parse("2026-07-31T09:10:00Z"));
    }
}
