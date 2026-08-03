package com.iflytek.skillhub.auth.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.iflytek.skillhub.auth.identity.ExternalIdentityLoginService;
import com.iflytek.skillhub.auth.identity.ExternalIdentityLinkService;
import com.iflytek.skillhub.auth.identity.IdentityCoreException;
import com.iflytek.skillhub.auth.identity.IdentityFailureCode;
import com.iflytek.skillhub.auth.identity.IdentityLinkActor;
import com.iflytek.skillhub.auth.identity.IdentityLinkBrowserFlow;
import com.iflytek.skillhub.auth.identity.IdentityLinkBrowserPhase;
import com.iflytek.skillhub.auth.identity.IdentityLinkOutcome;
import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
import com.iflytek.skillhub.auth.identity.IdentityLoginOutcome;
import com.iflytek.skillhub.auth.identity.IdentityLinkSessionManager;
import com.iflytek.skillhub.auth.identity.ProtocolAuthenticationEvidence;
import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;
import com.iflytek.skillhub.auth.identity.ProviderAttributeTrust;
import com.iflytek.skillhub.auth.identity.ProviderAttributeValue;
import com.iflytek.skillhub.auth.identity.ResolvedProviderHandle;
import com.iflytek.skillhub.auth.identity.ResolvedProviderHandleTestFixture;
import com.iflytek.skillhub.auth.identity.SubjectCandidate;
import com.iflytek.skillhub.auth.identity.TrustedProviderRouteResolver;
import com.iflytek.skillhub.auth.merge.AccountMergeProviderProofService;
import com.iflytek.skillhub.auth.merge.AccountMergeSessionManager;
import com.iflytek.skillhub.auth.merge.AccountMergeActor;
import com.iflytek.skillhub.auth.merge.AccountMergeBrowserFlow;
import com.iflytek.skillhub.auth.merge.AccountMergeIntent;
import com.iflytek.skillhub.auth.merge.AccountMergeIntentStatus;
import com.iflytek.skillhub.auth.merge.AccountMergePrimaryProof;
import com.iflytek.skillhub.auth.merge.AccountMergeProviderPrimaryProof;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import jakarta.servlet.http.HttpSession;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.client.RestTemplate;

class OAuthLoginFlowServiceTest {

    @AfterEach
    void resetRequestContext() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void resolvesReadyRouteBeforeOAuthUpstreamAndAdapterCalls() {
        OAuthClaimsExtractor extractor = mock(OAuthClaimsExtractor.class);
        when(extractor.getProvider()).thenReturn("github");
        TrustedProviderRouteResolver resolver =
                mock(TrustedProviderRouteResolver.class);
        ExternalIdentityLoginService identityLoginService =
                mock(ExternalIdentityLoginService.class);
        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate =
                mock();
        OAuth2UserRequest request = mock(OAuth2UserRequest.class);
        OAuth2User upstreamUser = mock(OAuth2User.class);
        ResolvedProviderHandle provider =
                ResolvedProviderHandleTestFixture.handle("github");
        ClientRegistration registration = registration();
        when(request.getClientRegistration()).thenReturn(registration);
        when(resolver.resolve(registration)).thenReturn(provider);
        when(delegate.loadUser(request)).thenReturn(upstreamUser);
        when(extractor.authenticate(any())).thenReturn(result());
        when(identityLoginService.authenticate(
                eq(provider),
                any(),
                eq(context())))
                .thenReturn(new IdentityLoginOutcome.Authenticated(
                        principal(),
                        false,
                        false));
        OAuthLoginFlowService service =
                new OAuthLoginFlowService(
                        List.of(extractor),
                        resolver,
                        identityLoginService,
                        mock(ExternalIdentityLinkService.class),
                        mock(IdentityLinkSessionManager.class),
                        mock(AccountMergeSessionManager.class),
                        mock(AccountMergeProviderProofService.class),
                        delegate);
        clearInvocations(extractor);

        service.loadLoginContext(request, context());

        InOrder order = inOrder(
                resolver,
                delegate,
                extractor,
                identityLoginService);
        order.verify(resolver).resolve(registration);
        order.verify(delegate).loadUser(request);
        order.verify(extractor).authenticate(any());
        order.verify(identityLoginService).authenticate(
                eq(provider),
                any(),
                eq(context()));
    }

    @Test
    void unavailableRouteCannotInvokeOAuthUpstreamOrAdapter() {
        OAuthClaimsExtractor extractor = mock(OAuthClaimsExtractor.class);
        when(extractor.getProvider()).thenReturn("github");
        TrustedProviderRouteResolver resolver =
                mock(TrustedProviderRouteResolver.class);
        ExternalIdentityLoginService identityLoginService =
                mock(ExternalIdentityLoginService.class);
        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate =
                mock();
        OAuth2UserRequest request = mock(OAuth2UserRequest.class);
        ClientRegistration registration = registration();
        when(request.getClientRegistration()).thenReturn(registration);
        when(resolver.resolve(registration)).thenThrow(
                new IdentityCoreException(
                        IdentityFailureCode.PROVIDER_DISABLED));
        OAuthLoginFlowService service =
                new OAuthLoginFlowService(
                        List.of(extractor),
                        resolver,
                        identityLoginService,
                        mock(ExternalIdentityLinkService.class),
                        mock(IdentityLinkSessionManager.class),
                        mock(AccountMergeSessionManager.class),
                        mock(AccountMergeProviderProofService.class),
                        delegate);
        clearInvocations(extractor);

        assertThatThrownBy(() ->
                service.loadLoginContext(request, context()))
                .isInstanceOfSatisfying(
                        OAuth2AuthenticationException.class,
                        exception -> assertThat(
                                exception.getError().getErrorCode())
                                .isEqualTo("provider_disabled"));

        verifyNoInteractions(delegate, identityLoginService);
        verify(extractor, never()).authenticate(any());
    }

    @Test
    void dingtalkCallbackUsesNativeUserInfoAndUnifiedIdentityCore() {
        OAuthClaimsExtractor extractor = new DingTalkClaimsExtractor();
        TrustedProviderRouteResolver resolver =
                mock(TrustedProviderRouteResolver.class);
        ExternalIdentityLoginService identityLoginService =
                mock(ExternalIdentityLoginService.class);
        ClientRegistration registration = dingtalkRegistration();
        ResolvedProviderHandle provider =
                ResolvedProviderHandleTestFixture.handle("dingtalk");
        when(resolver.resolve(registration)).thenReturn(provider);
        when(identityLoginService.authenticate(
                eq(provider),
                any(ProviderAuthenticationResult.class),
                eq(context())))
                .thenReturn(new IdentityLoginOutcome.Authenticated(
                        principal(),
                        false,
                        false));

        DingTalkProperties properties = new DingTalkProperties();
        properties.setEnabled(true);
        properties.setAuthority("dingtalk.corp");
        RestTemplate restTemplate = new RestTemplate();
        MockRestServiceServer server =
                MockRestServiceServer.bindTo(restTemplate).build();
        server.expect(requestTo(DingTalkOAuth2Constants.USER_INFO_URI))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header(
                        DingTalkOAuth2Constants.ACCESS_TOKEN_HEADER,
                        "access-token"))
                .andRespond(withSuccess(
                        """
                        {
                          "unionId":"union-123",
                          "openId":"open-456",
                          "userId":"user-789",
                          "nick":"Alice",
                          "email":"alice@example.com"
                        }
                        """,
                        MediaType.APPLICATION_JSON));

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "access-token",
                Instant.parse("2026-08-03T00:00:00Z"),
                Instant.parse("2026-08-03T01:00:00Z"));
        OAuth2UserRequest request = new OAuth2UserRequest(
                registration,
                accessToken);
        OAuthLoginFlowService service = new OAuthLoginFlowService(
                List.of(extractor),
                resolver,
                identityLoginService,
                mock(ExternalIdentityLinkService.class),
                mock(IdentityLinkSessionManager.class),
                mock(AccountMergeSessionManager.class),
                mock(AccountMergeProviderProofService.class),
                new DingTalkOAuth2UserService(
                        properties,
                        new com.fasterxml.jackson.databind.ObjectMapper(),
                        restTemplate));

        service.loadLoginContext(request, context());

        var result = org.mockito.ArgumentCaptor.forClass(
                ProviderAuthenticationResult.class);
        verify(identityLoginService).authenticate(
                eq(provider),
                result.capture(),
                eq(context()));
        assertThat(result.getValue().primarySubject())
                .isEqualTo(new SubjectCandidate(
                        "dingtalk_union_id",
                        "union-123"));
        assertThat(result.getValue().alternateSubjects())
                .containsExactly(
                        new SubjectCandidate("dingtalk_open_id", "open-456"),
                        new SubjectCandidate("dingtalk_user_id", "user-789"));
        assertThat(result.getValue().attributes())
                .containsEntry(
                        "dingtalk_email",
                        List.of(new ProviderAttributeValue(
                                "alice@example.com",
                                ProviderAttributeTrust.ASSERTED)));
        server.verify();
    }

    @Test
    void authenticateReturnsPrincipalOnlyForAuthenticatedOutcome() {
        TrustedProviderRouteResolver resolver =
                mock(TrustedProviderRouteResolver.class);
        ExternalIdentityLoginService identityLoginService =
                mock(ExternalIdentityLoginService.class);
        OAuthLoginFlowService service =
                new OAuthLoginFlowService(
                        List.of(),
                        resolver,
                        identityLoginService,
                        mock(ExternalIdentityLinkService.class),
                        mock(IdentityLinkSessionManager.class),
                        mock(AccountMergeSessionManager.class),
                        mock(AccountMergeProviderProofService.class));
        PlatformPrincipal principal = principal();
        when(identityLoginService.authenticate(any(), any(), any()))
                .thenReturn(new IdentityLoginOutcome.Authenticated(
                        principal,
                        false,
                        false));
        ClientRegistration registration = registration();
        IdentityLoginContext context = context();

        PlatformPrincipal authenticated =
                service.authenticate(registration, result(), context);

        assertThat(authenticated).isSameAs(principal);
        verify(resolver).resolve(registration);
        verify(identityLoginService).authenticate(
                any(),
                any(),
                org.mockito.ArgumentMatchers.eq(context));
    }

    @Test
    void pendingOutcomeUsesExistingPendingFailureContract() {
        TrustedProviderRouteResolver resolver =
                mock(TrustedProviderRouteResolver.class);
        ExternalIdentityLoginService identityLoginService =
                mock(ExternalIdentityLoginService.class);
        OAuthLoginFlowService service =
                new OAuthLoginFlowService(
                        List.of(),
                        resolver,
                        identityLoginService,
                        mock(ExternalIdentityLinkService.class),
                        mock(IdentityLinkSessionManager.class),
                        mock(AccountMergeSessionManager.class),
                        mock(AccountMergeProviderProofService.class));
        when(identityLoginService.authenticate(any(), any(), any()))
                .thenReturn(new IdentityLoginOutcome.PendingApproval(
                        "ACCOUNT_PENDING"));

        assertThatThrownBy(() ->
                service.authenticate(
                        registration(),
                        result(),
                        context()))
                .isInstanceOf(AccountPendingException.class);
    }

    @Test
    void linkRequiredOutcomeExposesOnlyGenericOAuthFailure() {
        TrustedProviderRouteResolver resolver =
                mock(TrustedProviderRouteResolver.class);
        ExternalIdentityLoginService identityLoginService =
                mock(ExternalIdentityLoginService.class);
        OAuthLoginFlowService service =
                new OAuthLoginFlowService(
                        List.of(),
                        resolver,
                        identityLoginService,
                        mock(ExternalIdentityLinkService.class),
                        mock(IdentityLinkSessionManager.class),
                        mock(AccountMergeSessionManager.class),
                        mock(AccountMergeProviderProofService.class));
        when(identityLoginService.authenticate(any(), any(), any()))
                .thenReturn(new IdentityLoginOutcome.LinkRequired(
                        "EMAIL_COLLISION"));

        assertThatThrownBy(() ->
                service.authenticate(
                        registration(),
                        result(),
                        context()))
                .isInstanceOfSatisfying(
                        OAuth2AuthenticationException.class,
                        exception -> {
                            assertThat(exception.getError()
                                    .getErrorCode())
                                    .isEqualTo("link_required");
                            assertThat(exception.getError()
                                    .getDescription())
                                    .isEqualTo(
                                            "Additional account verification is required")
                                    .doesNotContain(
                                            "EMAIL_COLLISION");
                        });
    }

    @Test
    void authorityMismatchIsMappedToStableOAuthFailure() {
        TrustedProviderRouteResolver resolver =
                mock(TrustedProviderRouteResolver.class);
        ExternalIdentityLoginService identityLoginService =
                mock(ExternalIdentityLoginService.class);
        OAuthLoginFlowService service =
                new OAuthLoginFlowService(
                        List.of(),
                        resolver,
                        identityLoginService,
                        mock(ExternalIdentityLinkService.class),
                        mock(IdentityLinkSessionManager.class),
                        mock(AccountMergeSessionManager.class),
                        mock(AccountMergeProviderProofService.class));
        when(identityLoginService.authenticate(any(), any(), any()))
                .thenThrow(new IdentityCoreException(
                        IdentityFailureCode.PROVIDER_AUTHORITY_MISMATCH));

        assertThatThrownBy(() ->
                service.authenticate(
                        registration(),
                        result(),
                        context()))
                .isInstanceOfSatisfying(
                        OAuth2AuthenticationException.class,
                        exception -> assertThat(
                                exception.getError().getErrorCode())
                                .isEqualTo(
                                        "provider_authority_mismatch"));
    }

    @Test
    void browserLinkFlowDoesNotRunNormalLoginOrReplacePrimaryAccount() {
        TrustedProviderRouteResolver resolver =
                mock(TrustedProviderRouteResolver.class);
        ExternalIdentityLoginService identityLoginService =
                mock(ExternalIdentityLoginService.class);
        ExternalIdentityLinkService identityLinkService =
                mock(ExternalIdentityLinkService.class);
        IdentityLinkSessionManager sessionManager =
                mock(IdentityLinkSessionManager.class);
        OAuthLoginFlowService service =
                new OAuthLoginFlowService(
                        List.of(),
                        resolver,
                        identityLoginService,
                        identityLinkService,
                        sessionManager,
                        mock(AccountMergeSessionManager.class),
                        mock(AccountMergeProviderProofService.class));
        ResolvedProviderHandle provider =
                ResolvedProviderHandleTestFixture.handle("github");
        UUID intentId = UUID.randomUUID();
        IdentityLinkActor actor = new IdentityLinkActor(
                "usr_1",
                "local",
                "high-entropy-session-nonce",
                context());
        MockHttpServletRequest request =
                new MockHttpServletRequest(
                        "GET",
                        "/login/oauth2/code/github");
        request.getSession(true);
        RequestContextHolder.setRequestAttributes(
                new ServletRequestAttributes(request));
        when(sessionManager.consumeBrowserFlow(
                request,
                "github",
                context()))
                .thenReturn(Optional.of(
                        new IdentityLinkBrowserFlow(
                                intentId,
                                IdentityLinkBrowserPhase.LINK,
                                actor)));
        when(identityLinkService.link(
                actor,
                intentId,
                provider,
                result()))
                .thenReturn(new IdentityLinkOutcome.Linked(
                        principal(),
                        42L));

        PlatformPrincipal linked = service.authenticate(
                provider,
                result(),
                context());

        assertThat(linked.userId()).isEqualTo("usr_1");
        verifyNoInteractions(identityLoginService);
        verify(sessionManager).remove(
                request.getSession(false),
                intentId);
    }

    @Test
    void primaryAccountMergeProofTakesPriorityAndKeepsPrimaryPrincipal() {
        ExternalIdentityLoginService identityLoginService =
                mock(ExternalIdentityLoginService.class);
        ExternalIdentityLinkService identityLinkService =
                mock(ExternalIdentityLinkService.class);
        IdentityLinkSessionManager identityLinkSessions =
                mock(IdentityLinkSessionManager.class);
        AccountMergeSessionManager accountMergeSessions =
                mock(AccountMergeSessionManager.class);
        AccountMergeProviderProofService proofService =
                mock(AccountMergeProviderProofService.class);
        OAuthLoginFlowService service =
                new OAuthLoginFlowService(
                        List.of(),
                        mock(TrustedProviderRouteResolver.class),
                        identityLoginService,
                        identityLinkService,
                        identityLinkSessions,
                        accountMergeSessions,
                        proofService);
        ResolvedProviderHandle provider =
                ResolvedProviderHandleTestFixture.handle("github");
        MockHttpServletRequest request =
                callbackRequest(principal());
        RequestContextHolder.setRequestAttributes(
                new ServletRequestAttributes(request));
        AccountMergeBrowserFlow flow =
                new AccountMergeBrowserFlow.Primary(
                        "usr_1",
                        "github");
        when(accountMergeSessions.consumeBrowserFlow(
                request,
                "github",
                context())).thenReturn(Optional.of(flow));
        when(proofService.completePrimary(
                request.getSession(false),
                provider,
                result(),
                context())).thenReturn(
                        new AccountMergeProviderPrimaryProof(
                                principal(),
                                new AccountMergePrimaryProof(
                                        "provider:github",
                                        Instant.parse(
                                                "2026-07-30T08:00:00Z"),
                                        Instant.parse(
                                                "2026-07-30T08:10:00Z"))));

        PlatformPrincipal authenticated = service.authenticate(
                provider,
                result(),
                context());

        assertThat(authenticated.userId()).isEqualTo("usr_1");
        verifyNoInteractions(
                identityLoginService,
                identityLinkService);
    }

    @Test
    void secondaryAccountMergeProofNeverReplacesPrimaryPrincipal() {
        ExternalIdentityLoginService identityLoginService =
                mock(ExternalIdentityLoginService.class);
        ExternalIdentityLinkService identityLinkService =
                mock(ExternalIdentityLinkService.class);
        AccountMergeSessionManager accountMergeSessions =
                mock(AccountMergeSessionManager.class);
        AccountMergeProviderProofService proofService =
                mock(AccountMergeProviderProofService.class);
        OAuthLoginFlowService service =
                new OAuthLoginFlowService(
                        List.of(),
                        mock(TrustedProviderRouteResolver.class),
                        identityLoginService,
                        identityLinkService,
                        mock(IdentityLinkSessionManager.class),
                        accountMergeSessions,
                        proofService);
        ResolvedProviderHandle provider =
                ResolvedProviderHandleTestFixture.handle("github");
        MockHttpServletRequest request =
                callbackRequest(principal());
        RequestContextHolder.setRequestAttributes(
                new ServletRequestAttributes(request));
        UUID intentId = UUID.randomUUID();
        AccountMergeActor actor = new AccountMergeActor(
                "usr_1",
                "local",
                "session-nonce",
                "local-password",
                Instant.parse("2026-07-30T08:00:00Z"),
                context());
        AccountMergeBrowserFlow.Secondary flow =
                new AccountMergeBrowserFlow.Secondary(
                        intentId,
                        actor,
                        "github");
        when(accountMergeSessions.consumeBrowserFlow(
                request,
                "github",
                context())).thenReturn(Optional.of(flow));
        when(proofService.completeSecondary(
                actor,
                intentId,
                provider,
                result(),
                context())).thenReturn(new AccountMergeIntent(
                        intentId,
                        AccountMergeIntentStatus.READY_FOR_PREVIEW,
                        Instant.parse(
                                "2026-07-30T08:10:00Z")));

        PlatformPrincipal authenticated = service.authenticate(
                provider,
                result(),
                context());

        assertThat(authenticated)
                .isEqualTo(
                        request.getSession(false)
                                .getAttribute("platformPrincipal"));
        assertThat(authenticated.userId()).isEqualTo("usr_1");
        verifyNoInteractions(
                identityLoginService,
                identityLinkService);
    }

    @Test
    void rememberReturnToStoresSanitizedReturnTarget() {
        OAuthLoginFlowService service = service();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("returnTo", "/dashboard/publish");

        service.rememberReturnTo(request);

        HttpSession session = request.getSession(false);
        assertThat(session).isNotNull();
        assertThat(session.getAttribute(
                OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE))
                .isEqualTo("/dashboard/publish");
    }

    @Test
    void resolveFailureRedirectMapsAccessDeniedToUserFacingPage() {
        OAuthLoginFlowService service = service();

        String redirect = service.resolveFailureRedirect(
                new OAuth2AuthenticationException(
                        new OAuth2Error("access_denied")),
                "/settings/accounts");

        assertThat(redirect).isEqualTo("/access-denied");
    }

    @Test
    void identityLinkFailureRedirectPreservesResumableIntent() {
        UUID intentId = UUID.randomUUID();

        String redirect = service().resolveFailureRedirect(
                new OAuth2AuthenticationException(
                        new OAuth2Error("identity_link_failed")),
                "/settings/security?identityLink=linked"
                        + "&intentId="
                        + intentId);

        assertThat(redirect)
                .isEqualTo(
                        "/settings/security?identityLink=failed"
                                + "&intentId="
                                + intentId);
    }

    @Test
    void identityLinkFailureRedirectIncludesStableReasonCode() {
        UUID intentId = UUID.randomUUID();

        String redirect = service().resolveFailureRedirect(
                new OAuth2AuthenticationException(
                        new OAuth2Error(
                                "identity_link_failed",
                                "PROVIDER_UNAVAILABLE",
                                null)),
                "/settings/security?identityLink=linked"
                        + "&intentId="
                        + intentId);

        assertThat(redirect)
                .isEqualTo(
                        "/settings/security?identityLink=failed"
                                + "&intentId="
                                + intentId
                                + "&reasonCode=PROVIDER_UNAVAILABLE");
    }

    @Test
    void resolveFailureRedirectMapsMergedAccountToAccessDenied() {
        assertThat(service().resolveFailureRedirect(
                new AccountMergedException(),
                null)).isEqualTo("/access-denied");
    }

    @Test
    void resolveFailureRedirectMapsSystemAccountToAccessDenied() {
        assertThat(service().resolveFailureRedirect(
                new SystemAccountLoginException(),
                null)).isEqualTo("/access-denied");
    }

    @Test
    void consumeReturnToClearsUnsafeSessionValue() {
        OAuthLoginFlowService service = service();
        MockHttpServletRequest request = new MockHttpServletRequest();
        HttpSession session = request.getSession(true);
        session.setAttribute(
                OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE,
                "https://evil.example");

        String returnTo = service.consumeReturnTo(session);

        assertThat(returnTo).isNull();
        assertThat(session.getAttribute(
                OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE))
                .isNull();
    }

    private static OAuthLoginFlowService service() {
        return new OAuthLoginFlowService(
                List.of(),
                mock(TrustedProviderRouteResolver.class),
                mock(ExternalIdentityLoginService.class),
                mock(ExternalIdentityLinkService.class),
                mock(IdentityLinkSessionManager.class),
                mock(AccountMergeSessionManager.class),
                mock(AccountMergeProviderProofService.class));
    }

    private static MockHttpServletRequest callbackRequest(
            PlatformPrincipal principal) {
        MockHttpServletRequest request =
                new MockHttpServletRequest(
                        "GET",
                        "/login/oauth2/code/github");
        request.getSession(true).setAttribute(
                "platformPrincipal",
                principal);
        return request;
    }

    private static ProviderAuthenticationResult result() {
        return new ProviderAuthenticationResult(
                new SubjectCandidate("github_user_id", "123"),
                List.of(),
                Map.of(),
                new ProtocolAuthenticationEvidence(
                        "oauth2-github",
                        Instant.parse("2026-07-30T08:00:00Z"),
                        Set.of("oauth2_authorization_code")));
    }

    private static IdentityLoginContext context() {
        return new IdentityLoginContext(
                "req-123",
                "203.0.113.9",
                "SkillHub Browser");
    }

    private static PlatformPrincipal principal() {
        return new PlatformPrincipal(
                "usr_1",
                "alice",
                "alice@example.com",
                null,
                "github",
                Set.of("USER"));
    }

    private static ClientRegistration registration() {
        return ClientRegistration.withRegistrationId("github")
                .clientId("client")
                .clientSecret("secret")
                .authorizationGrantType(
                        AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(
                        "{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri(
                        "https://github.com/login/oauth/authorize")
                .tokenUri(
                        "https://github.com/login/oauth/access_token")
                .userInfoUri("https://api.github.com/user")
                .userNameAttributeName("id")
                .clientName("GitHub")
                .build();
    }

    private static ClientRegistration dingtalkRegistration() {
        return ClientRegistration.withRegistrationId("dingtalk")
                .clientId("client-id")
                .clientSecret("client-secret")
                .authorizationGrantType(
                        AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(
                        "{baseUrl}/login/oauth2/code/{registrationId}")
                .scope(DingTalkOAuth2Constants.AUTHORIZATION_SCOPE)
                .authorizationUri(DingTalkOAuth2Constants.AUTHORIZATION_URI)
                .tokenUri(DingTalkOAuth2Constants.TOKEN_URI)
                .userInfoUri(DingTalkOAuth2Constants.USER_INFO_URI)
                .userNameAttributeName(
                        DingTalkOAuth2Constants.SUBJECT_ATTRIBUTE)
                .clientName("DingTalk")
                .build();
    }
}
