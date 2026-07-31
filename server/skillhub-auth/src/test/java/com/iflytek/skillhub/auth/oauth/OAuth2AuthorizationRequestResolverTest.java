package com.iflytek.skillhub.auth.oauth;

import com.iflytek.skillhub.auth.identity.ExternalIdentityLoginService;
import com.iflytek.skillhub.auth.identity.ExternalIdentityLinkService;
import com.iflytek.skillhub.auth.identity.IdentityLinkSessionManager;
import com.iflytek.skillhub.auth.identity.TrustedProviderRouteResolver;
import com.iflytek.skillhub.auth.merge.AccountMergeProviderProofService;
import com.iflytek.skillhub.auth.merge.AccountMergeSessionManager;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.auth.session.PlatformSessionService;
import jakarta.servlet.http.HttpSession;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class OAuth2AuthorizationRequestResolverTest {

    private SkillHubOAuth2AuthorizationRequestResolver resolver;
    private OAuthLoginFlowService oauthLoginFlowService;
    private AccountMergeSessionManager accountMergeSessionManager;

    @BeforeEach
    void setUp() {
        ClientRegistration github = ClientRegistration.withRegistrationId("github")
                .clientId("client")
                .clientSecret("secret")
                .authorizationUri("https://example.test/oauth/authorize")
                .tokenUri("https://example.test/oauth/token")
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .userInfoUri("https://example.test/user")
                .userNameAttributeName("id")
                .authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE)
                .scope("read:user")
                .clientName("GitHub")
                .build();
        oauthLoginFlowService = new OAuthLoginFlowService(
                java.util.List.of(),
                mock(TrustedProviderRouteResolver.class),
                mock(ExternalIdentityLoginService.class),
                mock(ExternalIdentityLinkService.class),
                mock(IdentityLinkSessionManager.class),
                mock(AccountMergeSessionManager.class),
                mock(AccountMergeProviderProofService.class)
        );
        accountMergeSessionManager =
                mock(AccountMergeSessionManager.class);
        resolver = new SkillHubOAuth2AuthorizationRequestResolver(
                new InMemoryClientRegistrationRepository(github),
                oauthLoginFlowService,
                mock(IdentityLinkSessionManager.class),
                accountMergeSessionManager
        );
    }

    @Test
    void resolve_preservesReturnToAcrossCallbackUntilSuccessHandler()
            throws Exception {
        String returnTo =
                "/settings/security?identityLink=linked"
                        + "&intentId=7d26c414-6040-48b5-b025-53a16b8aa6b9";
        MockHttpServletRequest authorizationRequest =
                oauthRequest("/oauth2/authorization/github");
        authorizationRequest.setParameter("returnTo", returnTo);

        assertThat(resolver.resolve(authorizationRequest)).isNotNull();

        MockHttpSession session =
                (MockHttpSession) authorizationRequest.getSession(false);
        assertThat(session).isNotNull();
        assertThat(session.getAttribute(
                OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE))
                .isEqualTo(returnTo);

        MockHttpServletRequest callbackRequest =
                oauthRequest("/login/oauth2/code/github");
        callbackRequest.setSession(session);
        assertThat(resolver.resolve(callbackRequest)).isNull();
        assertThat(session.getAttribute(
                OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE))
                .isEqualTo(returnTo);

        OAuth2LoginSuccessHandler successHandler =
                new OAuth2LoginSuccessHandler(
                        new PlatformSessionService(),
                        oauthLoginFlowService);
        MockHttpServletResponse response =
                new MockHttpServletResponse();
        successHandler.onAuthenticationSuccess(
                callbackRequest,
                response,
                oauthAuthentication());

        assertThat(response.getRedirectedUrl()).isEqualTo(returnTo);
        assertThat(session.getAttribute(
                OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE))
                .isNull();
    }

    @Test
    void resolve_storesSanitizedReturnToInSession() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/authorization/github");
        request.setParameter("returnTo", "/dashboard/publish?draft=1");

        resolver.resolve(request, "github");

        HttpSession session = request.getSession(false);
        assertThat(session).isNotNull();
        assertThat(session.getAttribute(OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE))
                .isEqualTo("/dashboard/publish?draft=1");
        verify(accountMergeSessionManager)
                .activateBrowserFlow(
                        eq(session),
                        eq("github"),
                        anyString());
    }

    @Test
    void resolve_ignoresUnsafeReturnTo() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/authorization/github");
        request.setParameter("returnTo", "https://evil.example");

        resolver.resolve(request, "github");

        HttpSession session = request.getSession(false);
        assertThat(session).isNotNull();
        assertThat(session.getAttribute(OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE)).isNull();
    }

    @Test
    void resolve_nonAuthorizationRequestDoesNotCreateSession() {
        MockHttpServletRequest request =
                oauthRequest("/login/oauth2/code/github");

        assertThat(resolver.resolve(request)).isNull();
        assertThat(request.getSession(false)).isNull();
    }

    private MockHttpServletRequest oauthRequest(String path) {
        MockHttpServletRequest request =
                new MockHttpServletRequest("GET", path);
        request.setServletPath(path);
        return request;
    }

    private Authentication oauthAuthentication() {
        PlatformPrincipal principal = new PlatformPrincipal(
                "user-1",
                "User",
                "user@example.com",
                null,
                "github",
                Set.of());
        return new UsernamePasswordAuthenticationToken(
                new DefaultOAuth2User(
                        List.of(),
                        Map.of(
                                "platformPrincipal",
                                principal,
                                "login",
                                "user"),
                        "login"),
                null,
                List.of());
    }
}
