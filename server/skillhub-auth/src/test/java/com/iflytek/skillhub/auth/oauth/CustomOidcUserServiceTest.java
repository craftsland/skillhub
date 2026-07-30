package com.iflytek.skillhub.auth.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.identity.ProviderAttributeTrust;
import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;
import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

class CustomOidcUserServiceTest {

    @Test
    void loadUserMapsOidcFactsThroughUnifiedLoginFlow() {
        OAuthLoginFlowService loginFlowService =
                mock(OAuthLoginFlowService.class);
        OAuth2UserService<OidcUserRequest, OidcUser> delegate = mock();
        OAuthIdentityLoginContextResolver contextResolver = mock();
        CustomOidcUserService service =
                new CustomOidcUserService(
                        loginFlowService,
                        delegate,
                        contextResolver);
        OidcUserRequest request = oidcRequest();
        IdentityLoginContext loginContext = context();
        OidcUser upstreamUser = oidcUser(Map.of(
                IdTokenClaimNames.SUB, "oidc-sub-1",
                "email", "user@example.com",
                "email_verified", true,
                "preferred_username", "preferred-user",
                "name", "Display User",
                "picture", "https://idp.example/avatar.png"));
        PlatformPrincipal platformPrincipal = new PlatformPrincipal(
                "usr_1",
                "Preferred User",
                "user@example.com",
                "https://idp.example/avatar.png",
                "okta",
                Set.of("USER", "SUPER_ADMIN"));
        when(delegate.loadUser(request)).thenReturn(upstreamUser);
        when(contextResolver.current()).thenReturn(loginContext);
        when(loginFlowService.authenticate(
                eq(request.getClientRegistration()),
                any(ProviderAuthenticationResult.class),
                eq(loginContext)))
                .thenReturn(platformPrincipal);

        OidcUser loadedUser = service.loadUser(request);

        ArgumentCaptor<ProviderAuthenticationResult> resultCaptor =
                ArgumentCaptor.forClass(
                        ProviderAuthenticationResult.class);
        verify(loginFlowService).authenticate(
                eq(request.getClientRegistration()),
                resultCaptor.capture(),
                eq(loginContext));
        ProviderAuthenticationResult result = resultCaptor.getValue();
        assertThat(result.primarySubject().type()).isEqualTo("oidc_sub");
        assertThat(result.primarySubject().value())
                .isEqualTo("oidc-sub-1");
        assertThat(result.attributes().get("email").getFirst().value())
                .isEqualTo("user@example.com");
        assertThat(result.attributes().get("email").getFirst().trust())
                .isEqualTo(ProviderAttributeTrust.VERIFIED);
        assertThat(result.attributes().get("preferred_username")
                .getFirst().value()).isEqualTo("preferred-user");
        assertThat(result.attributes().get("picture").getFirst().value())
                .isEqualTo("https://idp.example/avatar.png");

        assertThat((Object) loadedUser.getAttribute("platformPrincipal"))
                .isEqualTo(platformPrincipal);
        assertThat((Object) loadedUser.getAttribute("providerLogin"))
                .isEqualTo("usr_1");
        assertThat(loadedUser.getName()).isEqualTo("usr_1");
        assertThat(loadedUser.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .contains("ROLE_USER", "ROLE_SUPER_ADMIN");
    }

    @Test
    void conversionPreservesUnverifiedEmailAsUntrustedFact() {
        ProviderAuthenticationResult result =
                CustomOidcUserService.toProviderAuthenticationResult(
                        oidcRequest(),
                        oidcUser(Map.of(
                                IdTokenClaimNames.SUB, "subject-3",
                                "email", "unverified@example.com",
                                "email_verified", false,
                                "name", "Fallback Name")));

        assertThat(result.primarySubject().value()).isEqualTo("subject-3");
        assertThat(result.attributes().get("email").getFirst().value())
                .isEqualTo("unverified@example.com");
        assertThat(result.attributes().get("email").getFirst().trust())
                .isEqualTo(ProviderAttributeTrust.UNVERIFIED);
        assertThat(result.attributes().get("name").getFirst().value())
                .isEqualTo("Fallback Name");
    }

    @Test
    void conversionTreatsAbsentEmailVerifiedAsUnverified() {
        ProviderAuthenticationResult result =
                CustomOidcUserService.toProviderAuthenticationResult(
                        oidcRequest(),
                        oidcUser(Map.of(
                                IdTokenClaimNames.SUB,
                                "subject-absent-verified",
                                "email",
                                "maybe@example.com")));

        assertThat(result.attributes().get("email").getFirst().trust())
                .isEqualTo(ProviderAttributeTrust.UNVERIFIED);
    }

    @Test
    void conversionThrowsWhenSubIsMissing() {
        OidcUser user = mock(OidcUser.class);
        when(user.getClaims())
                .thenReturn(Map.of("email", "no-sub@example.com"));

        assertThatThrownBy(() ->
                CustomOidcUserService.toProviderAuthenticationResult(
                        oidcRequest(),
                        user))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .hasMessageContaining("sub");
    }

    @Test
    void conversionThrowsWhenSubIsBlank() {
        OidcUser user = mock(OidcUser.class);
        when(user.getClaims())
                .thenReturn(Map.of(IdTokenClaimNames.SUB, "   "));

        assertThatThrownBy(() ->
                CustomOidcUserService.toProviderAuthenticationResult(
                        oidcRequest(),
                        user))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .hasMessageContaining("sub");
    }

    @Test
    void conversionUsesExactCaseSensitiveSubWhenProfileIsAbsent() {
        ProviderAuthenticationResult result =
                CustomOidcUserService.toProviderAuthenticationResult(
                        oidcRequest(),
                        oidcUser(Map.of(
                                IdTokenClaimNames.SUB,
                                "CaseSensitiveSubject")));

        assertThat(result.primarySubject().value())
                .isEqualTo("CaseSensitiveSubject");
        assertThat(result.attributes().get("sub").getFirst().value())
                .isEqualTo("CaseSensitiveSubject");
        assertThat(result.attributes()).doesNotContainKey("email");
    }

    @Test
    void deniedUnverifiedEmailStillReachesCoreWithUnverifiedTrust() {
        OAuthLoginFlowService loginFlowService =
                mock(OAuthLoginFlowService.class);
        OAuth2UserService<OidcUserRequest, OidcUser> delegate = mock();
        OAuthIdentityLoginContextResolver contextResolver = mock();
        CustomOidcUserService service =
                new CustomOidcUserService(
                        loginFlowService,
                        delegate,
                        contextResolver);
        OidcUserRequest request = oidcRequest();
        IdentityLoginContext loginContext = context();
        OidcUser upstreamUser = oidcUser(Map.of(
                IdTokenClaimNames.SUB, "oidc-sub-unverified",
                "email", "user@company.com",
                "email_verified", false,
                "preferred_username", "unverified-user"));
        when(delegate.loadUser(request)).thenReturn(upstreamUser);
        when(contextResolver.current()).thenReturn(loginContext);

        ArgumentCaptor<ProviderAuthenticationResult> resultCaptor =
                ArgumentCaptor.forClass(
                        ProviderAuthenticationResult.class);
        when(loginFlowService.authenticate(
                eq(request.getClientRegistration()),
                resultCaptor.capture(),
                eq(loginContext)))
                .thenThrow(new OAuth2AuthenticationException(
                        new org.springframework.security.oauth2.core.OAuth2Error(
                                "access_denied")));

        assertThatThrownBy(() -> service.loadUser(request))
                .isInstanceOf(OAuth2AuthenticationException.class);

        ProviderAuthenticationResult captured = resultCaptor.getValue();
        assertThat(captured.attributes().get("email")
                .getFirst().trust())
                .isEqualTo(ProviderAttributeTrust.UNVERIFIED);
        assertThat(captured.primarySubject().value())
                .isEqualTo("oidc-sub-unverified");
    }

    private static OidcUserRequest oidcRequest() {
        Instant issuedAt = Instant.parse("2026-04-24T00:00:00Z");
        OidcIdToken idToken = new OidcIdToken(
                "id-token",
                issuedAt,
                issuedAt.plusSeconds(300),
                Map.of(IdTokenClaimNames.SUB, "request-sub"));
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "access-token",
                issuedAt,
                issuedAt.plusSeconds(300));
        return new OidcUserRequest(
                clientRegistration(),
                accessToken,
                idToken);
    }

    private static IdentityLoginContext context() {
        return new IdentityLoginContext(
                "req-123",
                "203.0.113.9",
                "SkillHub Browser");
    }

    private static OidcUser oidcUser(Map<String, Object> claims) {
        Instant issuedAt = Instant.parse("2026-04-24T00:00:00Z");
        OidcIdToken idToken = new OidcIdToken(
                "id-token",
                issuedAt,
                issuedAt.plusSeconds(300),
                claims);
        return new DefaultOidcUser(
                List.of(new SimpleGrantedAuthority("OIDC_USER")),
                idToken,
                new OidcUserInfo(claims));
    }

    private static ClientRegistration clientRegistration() {
        return ClientRegistration.withRegistrationId("okta")
                .clientId("client")
                .clientSecret("secret")
                .authorizationGrantType(
                        AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(
                        "https://skillhub.example/login/oauth2/code/okta")
                .authorizationUri(
                        "https://idp.example/oauth2/v1/authorize")
                .tokenUri("https://idp.example/oauth2/v1/token")
                .jwkSetUri("https://idp.example/oauth2/v1/keys")
                .userInfoUri(
                        "https://idp.example/oauth2/v1/userinfo")
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .scope("openid", "profile", "email")
                .build();
    }
}
