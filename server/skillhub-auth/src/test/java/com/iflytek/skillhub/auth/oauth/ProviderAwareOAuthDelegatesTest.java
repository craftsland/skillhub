package com.iflytek.skillhub.auth.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.user.OAuth2User;

class ProviderAwareOAuthDelegatesTest {

    @Test
    void routesOnlyDingTalkRegistrationToNativeUserInfoAdapter() {
        OAuth2UserService<OAuth2UserRequest, OAuth2User> standard = mock();
        OAuth2UserService<OAuth2UserRequest, OAuth2User> dingtalk = mock();
        OAuth2UserRequest request = mock();
        OAuth2User result = mock();
        when(request.getClientRegistration())
                .thenReturn(registration("dingtalk"));
        when(dingtalk.loadUser(request)).thenReturn(result);

        OAuth2User actual = new ProviderAwareOAuth2UserService(
                standard,
                dingtalk).loadUser(request);

        assertThat(actual).isSameAs(result);
        verify(dingtalk).loadUser(request);
        verifyNoInteractions(standard);
    }

    @Test
    void preservesStandardUserInfoAdapterForOtherRegistrations() {
        OAuth2UserService<OAuth2UserRequest, OAuth2User> standard = mock();
        OAuth2UserService<OAuth2UserRequest, OAuth2User> dingtalk = mock();
        OAuth2UserRequest request = mock();
        OAuth2User result = mock();
        when(request.getClientRegistration())
                .thenReturn(registration("github"));
        when(standard.loadUser(request)).thenReturn(result);

        OAuth2User actual = new ProviderAwareOAuth2UserService(
                standard,
                dingtalk).loadUser(request);

        assertThat(actual).isSameAs(result);
        verify(standard).loadUser(request);
        verifyNoInteractions(dingtalk);
    }

    @Test
    void routesOnlyDingTalkRegistrationToNativeTokenAdapter() {
        OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>
                standard = mock();
        OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>
                dingtalk = mock();
        OAuth2AuthorizationCodeGrantRequest request = mock();
        OAuth2AccessTokenResponse result =
                OAuth2AccessTokenResponse.withToken("access-123")
                        .tokenType(TokenType.BEARER)
                        .build();
        when(request.getClientRegistration())
                .thenReturn(registration("dingtalk"));
        when(dingtalk.getTokenResponse(request)).thenReturn(result);

        OAuth2AccessTokenResponse actual =
                new ProviderAwareAccessTokenResponseClient(
                        standard,
                        dingtalk).getTokenResponse(request);

        assertThat(actual).isSameAs(result);
        verify(dingtalk).getTokenResponse(request);
        verifyNoInteractions(standard);
    }

    private static ClientRegistration registration(String registrationId) {
        return ClientRegistration.withRegistrationId(registrationId)
                .clientId("client-id")
                .clientSecret("client-secret")
                .clientName(registrationId)
                .authorizationGrantType(
                        AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri("https://login.example/authorize")
                .tokenUri("https://login.example/token")
                .userInfoUri("https://login.example/userinfo")
                .userNameAttributeName("id")
                .build();
    }
}
