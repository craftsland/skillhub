package com.iflytek.skillhub.auth.oauth;

import com.iflytek.skillhub.auth.identity.IdentityLinkSessionManager;
import com.iflytek.skillhub.auth.identity.IdentityLinkFailureCode;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class OAuth2LoginHandlersTest {

    @Test
    void successHandler_redirectsToStoredReturnTo() throws Exception {
        OAuthLoginFlowService oauthLoginFlowService = mock(OAuthLoginFlowService.class);
        OAuth2LoginSuccessHandler handler = new OAuth2LoginSuccessHandler(
                new com.iflytek.skillhub.auth.session.PlatformSessionService(),
                oauthLoginFlowService
        );
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        HttpSession session = request.getSession(true);
        String originalSessionId = session.getId();
        session.setAttribute(OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE, "/dashboard/publish");

        var principal = new com.iflytek.skillhub.auth.rbac.PlatformPrincipal(
                "user-1", "User", "user@example.com", null, "github", Set.of()
        );
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                new DefaultOAuth2User(List.of(), Map.of("platformPrincipal", principal, "login", "user"), "login"),
                null,
                List.of()
        );

        org.mockito.Mockito.when(oauthLoginFlowService.consumeReturnTo(org.mockito.ArgumentMatchers.any()))
                .thenAnswer(invocation -> {
                    HttpSession currentSession = invocation.getArgument(0);
                    Object value = currentSession.getAttribute(OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE);
                    currentSession.removeAttribute(OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE);
                    return value;
                });

        handler.onAuthenticationSuccess(request, response, authentication);

        SecurityContext securityContext = (SecurityContext) session.getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY
        );
        assertThat(response.getRedirectedUrl()).isEqualTo("/dashboard/publish");
        assertThat(request.getSession(false).getId()).isEqualTo(originalSessionId);
        assertThat(session.getAttribute(OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE)).isNull();
        assertThat(session.getAttribute("platformPrincipal")).isEqualTo(principal);
        assertThat(securityContext).isNotNull();
        assertThat(securityContext.getAuthentication().getPrincipal()).isEqualTo(principal);
    }

    /**
     * Regression test: when an unauthenticated client hits a protected API endpoint, Spring Security
     * caches that request. With {@code SavedRequestAwareAuthenticationSuccessHandler} the post-login
     * redirect would resolve to the cached API URL, leaving the user staring at raw JSON instead of
     * the dashboard. The handler must ignore the saved request and fall back to the default target.
     */
    @Test
    void successHandler_ignoresSavedApiRequestAndRedirectsToDefault() throws Exception {
        OAuthLoginFlowService oauthLoginFlowService = mock(OAuthLoginFlowService.class);
        OAuth2LoginSuccessHandler handler = new OAuth2LoginSuccessHandler(
                new com.iflytek.skillhub.auth.session.PlatformSessionService(),
                oauthLoginFlowService
        );
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        request.setRequestURI("/api/web/skills");
        MockHttpServletResponse response = new MockHttpServletResponse();
        // Simulate Spring Security saving the API request that triggered login.
        new HttpSessionRequestCache().saveRequest(request, response);

        var principal = new com.iflytek.skillhub.auth.rbac.PlatformPrincipal(
                "user-1", "User", "user@example.com", null, "github", Set.of()
        );
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                new DefaultOAuth2User(List.of(), Map.of("platformPrincipal", principal, "login", "user"), "login"),
                null,
                List.of()
        );
        org.mockito.Mockito.when(oauthLoginFlowService.consumeReturnTo(org.mockito.ArgumentMatchers.any()))
                .thenReturn(null);

        handler.onAuthenticationSuccess(request, response, authentication);

        assertThat(response.getRedirectedUrl()).isEqualTo("/dashboard");
    }

    @Test
    void failureHandler_redirectsBackToLoginWithReturnTo() throws Exception {
        OAuthLoginFlowService oauthLoginFlowService = mock(OAuthLoginFlowService.class);
        OAuth2LoginFailureHandler handler = new OAuth2LoginFailureHandler(
                oauthLoginFlowService,
                mock(IdentityLinkSessionManager.class));
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        HttpSession session = request.getSession(true);
        session.setAttribute(OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE, "/settings/accounts");
        org.mockito.Mockito.when(oauthLoginFlowService.consumeReturnTo(org.mockito.ArgumentMatchers.any()))
                .thenAnswer(invocation -> {
                    HttpSession currentSession = invocation.getArgument(0);
                    Object value = currentSession.getAttribute(OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE);
                    currentSession.removeAttribute(OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE);
                    return value;
                });
        org.mockito.Mockito.when(oauthLoginFlowService.resolveFailureRedirect(
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.eq("/settings/accounts")))
                .thenReturn("/login?returnTo=%2Fsettings%2Faccounts");

        handler.onAuthenticationFailure(
                request,
                response,
                new OAuth2AuthenticationException(new OAuth2Error("invalid_request"))
        );

        assertThat(response.getRedirectedUrl()).isEqualTo("/login?returnTo=%2Fsettings%2Faccounts");
        assertThat(session.getAttribute(OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE)).isNull();
    }

    @Test
    void failureHandler_preservesIdentityLinkIntentForRetry()
            throws Exception {
        OAuthLoginFlowService oauthLoginFlowService =
                mock(OAuthLoginFlowService.class);
        IdentityLinkSessionManager sessionManager =
                mock(IdentityLinkSessionManager.class);
        OAuth2LoginFailureHandler handler =
                new OAuth2LoginFailureHandler(
                        oauthLoginFlowService,
                        sessionManager);
        MockHttpServletRequest request =
                new MockHttpServletRequest();
        MockHttpServletResponse response =
                new MockHttpServletResponse();
        HttpSession session = request.getSession(true);
        UUID intentId = UUID.randomUUID();
        org.mockito.Mockito.when(
                sessionManager.consumeFailedBrowserFlow(session))
                .thenReturn(Optional.of(intentId));

        handler.onAuthenticationFailure(
                request,
                response,
                new OAuth2AuthenticationException(
                        new OAuth2Error("access_denied")));

        assertThat(response.getRedirectedUrl())
                .isEqualTo(
                        "/settings/security?identityLink=failed"
                                + "&intentId="
                                + intentId
                                + "&reasonCode="
                                + "PROVIDER_AUTHENTICATION_FAILED");
        org.mockito.Mockito.verify(
                oauthLoginFlowService,
                org.mockito.Mockito.never())
                .resolveFailureRedirect(
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any());
    }

    @Test
    void failureHandler_preservesStableIdentityLinkReasonCode()
            throws Exception {
        OAuthLoginFlowService oauthLoginFlowService =
                mock(OAuthLoginFlowService.class);
        IdentityLinkSessionManager sessionManager =
                mock(IdentityLinkSessionManager.class);
        OAuth2LoginFailureHandler handler =
                new OAuth2LoginFailureHandler(
                        oauthLoginFlowService,
                        sessionManager);
        MockHttpServletRequest request =
                new MockHttpServletRequest();
        MockHttpServletResponse response =
                new MockHttpServletResponse();
        HttpSession session = request.getSession(true);
        UUID intentId = UUID.randomUUID();
        OAuth2AuthenticationException failure =
                new OAuth2AuthenticationException(
                        new OAuth2Error(
                                "identity_link_failed",
                                "PROVIDER_UNAVAILABLE",
                                null));
        org.mockito.Mockito.when(
                sessionManager.consumeFailedBrowserFlow(session))
                .thenReturn(Optional.of(intentId));
        org.mockito.Mockito.when(
                oauthLoginFlowService
                        .identityLinkFailureReasonCode(failure))
                .thenReturn(Optional.of(
                        "PROVIDER_UNAVAILABLE"));

        handler.onAuthenticationFailure(
                request,
                response,
                failure);

        assertThat(response.getRedirectedUrl())
                .isEqualTo(
                        "/settings/security?identityLink=failed"
                                + "&intentId="
                                + intentId
                                + "&reasonCode=PROVIDER_UNAVAILABLE");
    }

    @Test
    void routeFailureRedirectsOnlyAnOwnedIdentityLinkFlow()
            throws Exception {
        OAuthLoginFlowService oauthLoginFlowService =
                mock(OAuthLoginFlowService.class);
        IdentityLinkSessionManager sessionManager =
                mock(IdentityLinkSessionManager.class);
        OAuth2LoginFailureHandler handler =
                new OAuth2LoginFailureHandler(
                        oauthLoginFlowService,
                        sessionManager);
        MockHttpServletRequest request =
                new MockHttpServletRequest();
        MockHttpServletResponse response =
                new MockHttpServletResponse();
        HttpSession session = request.getSession(true);
        UUID intentId = UUID.randomUUID();
        org.mockito.Mockito.when(
                sessionManager.consumeFailedBrowserFlow(session))
                .thenReturn(Optional.of(intentId));

        boolean redirected =
                handler.redirectIdentityLinkRouteFailure(
                        request,
                        response,
                        IdentityLinkFailureCode.PROVIDER_UNAVAILABLE);

        assertThat(redirected).isTrue();
        assertThat(response.getRedirectedUrl())
                .isEqualTo(
                        "/settings/security?identityLink=failed"
                                + "&intentId="
                                + intentId
                                + "&reasonCode=PROVIDER_UNAVAILABLE");
        org.mockito.Mockito.verify(oauthLoginFlowService)
                .consumeReturnTo(session);
    }
}
