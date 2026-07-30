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

import com.iflytek.skillhub.auth.identity.ExternalIdentityLoginService;
import com.iflytek.skillhub.auth.identity.IdentityCoreException;
import com.iflytek.skillhub.auth.identity.IdentityFailureCode;
import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
import com.iflytek.skillhub.auth.identity.IdentityLoginOutcome;
import com.iflytek.skillhub.auth.identity.ProtocolAuthenticationEvidence;
import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;
import com.iflytek.skillhub.auth.identity.ResolvedProviderHandle;
import com.iflytek.skillhub.auth.identity.SubjectCandidate;
import com.iflytek.skillhub.auth.identity.TrustedProviderRouteResolver;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import jakarta.servlet.http.HttpSession;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;

class OAuthLoginFlowServiceTest {

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
                mock(ResolvedProviderHandle.class);
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
    void authenticateReturnsPrincipalOnlyForAuthenticatedOutcome() {
        TrustedProviderRouteResolver resolver =
                mock(TrustedProviderRouteResolver.class);
        ExternalIdentityLoginService identityLoginService =
                mock(ExternalIdentityLoginService.class);
        OAuthLoginFlowService service =
                new OAuthLoginFlowService(
                        List.of(),
                        resolver,
                        identityLoginService);
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
                        identityLoginService);
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
                        identityLoginService);
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
                        identityLoginService);
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
                mock(ExternalIdentityLoginService.class));
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
}
