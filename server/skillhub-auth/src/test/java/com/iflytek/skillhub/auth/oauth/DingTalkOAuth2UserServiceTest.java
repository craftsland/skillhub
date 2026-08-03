package com.iflytek.skillhub.auth.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

class DingTalkOAuth2UserServiceTest {

    @Test
    void loadsOfficialUserInfoWithDingTalkAccessTokenHeader() {
        DingTalkProperties properties = enabledProperties();
        RestTemplate restTemplate = new RestTemplate();
        MockRestServiceServer server =
                MockRestServiceServer.bindTo(restTemplate).build();
        server.expect(requestTo(DingTalkOAuth2Constants.USER_INFO_URI))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header(
                        DingTalkOAuth2Constants.ACCESS_TOKEN_HEADER,
                        "token-123"))
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

        OAuth2User user = new DingTalkOAuth2UserService(
                properties,
                new com.fasterxml.jackson.databind.ObjectMapper(),
                restTemplate).loadUser(userRequest());

        assertThat(user.getName()).isEqualTo("union-123");
        assertThat(user.getAttributes())
                .containsEntry("unionId", "union-123")
                .containsEntry("openId", "open-456");
        server.verify();
    }

    @Test
    void disabledProviderFailsBeforeMakingUserInfoRequest() {
        DingTalkProperties properties = new DingTalkProperties();
        RestTemplate restTemplate = new RestTemplate();
        MockRestServiceServer server =
                MockRestServiceServer.bindTo(restTemplate).build();

        assertThatThrownBy(() -> new DingTalkOAuth2UserService(
                properties,
                new com.fasterxml.jackson.databind.ObjectMapper(),
                restTemplate).loadUser(userRequest()))
                .isInstanceOfSatisfying(
                        OAuth2AuthenticationException.class,
                        exception -> assertThat(
                                exception.getError().getErrorCode())
                                .isEqualTo("dingtalk_provider_misconfigured"));

        server.verify();
    }

    @Test
    void missingAccessTokenFailsBeforeMakingUserInfoRequest() {
        DingTalkProperties properties = enabledProperties();
        RestTemplate restTemplate = new RestTemplate();
        MockRestServiceServer server =
                MockRestServiceServer.bindTo(restTemplate).build();
        OAuth2UserRequest request = mock(OAuth2UserRequest.class);
        when(request.getClientRegistration())
                .thenReturn(userRequest().getClientRegistration());
        when(request.getAccessToken()).thenReturn(null);

        assertThatThrownBy(() -> new DingTalkOAuth2UserService(
                properties,
                new com.fasterxml.jackson.databind.ObjectMapper(),
                restTemplate).loadUser(request))
                .isInstanceOfSatisfying(
                        OAuth2AuthenticationException.class,
                        exception -> assertThat(
                                exception.getError().getErrorCode())
                                .isEqualTo("access_token_missing"));
        server.verify();
    }

    @Test
    void oversizedUserInfoResponseFailsWithoutParsingOrReturningUpstreamData() {
        DingTalkProperties properties = enabledProperties();
        properties.setMaxResponseBytes(1024);
        RestTemplate restTemplate = new RestTemplate();
        MockRestServiceServer server =
                MockRestServiceServer.bindTo(restTemplate).build();
        server.expect(requestTo(DingTalkOAuth2Constants.USER_INFO_URI))
                .andRespond(withSuccess(
                        "{" + "\"unionId\":\"union-123\",\"padding\":\""
                                + "x".repeat(1100) + "\"}",
                        MediaType.APPLICATION_JSON));

        assertThatThrownBy(() -> new DingTalkOAuth2UserService(
                properties,
                new com.fasterxml.jackson.databind.ObjectMapper(),
                restTemplate).loadUser(userRequest()))
                .isInstanceOfSatisfying(
                        OAuth2AuthenticationException.class,
                        exception -> assertThat(
                                exception.getError().getErrorCode())
                                .isEqualTo("userinfo_response_too_large"));
        server.verify();
    }

    @Test
    void rejectsRegistrationWithUntrustedAuthorizationEndpointBeforeNetwork() {
        DingTalkProperties properties = enabledProperties();
        RestTemplate restTemplate = new RestTemplate();
        MockRestServiceServer server =
                MockRestServiceServer.bindTo(restTemplate).build();

        assertThatThrownBy(() -> new DingTalkOAuth2UserService(
                properties,
                new com.fasterxml.jackson.databind.ObjectMapper(),
                restTemplate).loadUser(userRequest(
                        "https://attacker.example/authorize",
                        DingTalkOAuth2Constants.TOKEN_URI,
                        DingTalkOAuth2Constants.USER_INFO_URI)))
                .isInstanceOfSatisfying(
                        OAuth2AuthenticationException.class,
                        exception -> assertThat(
                                exception.getError().getErrorCode())
                                .isEqualTo("dingtalk_provider_misconfigured"));

        server.verify();
    }

    private static DingTalkProperties enabledProperties() {
        DingTalkProperties properties = new DingTalkProperties();
        properties.setEnabled(true);
        properties.setAuthority("dingtalk.corp");
        return properties;
    }

    private static OAuth2UserRequest userRequest() {
        return userRequest(
                DingTalkOAuth2Constants.AUTHORIZATION_URI,
                DingTalkOAuth2Constants.TOKEN_URI,
                DingTalkOAuth2Constants.USER_INFO_URI);
    }

    private static OAuth2UserRequest userRequest(
            String authorizationUri,
            String tokenUri,
            String userInfoUri) {
        ClientRegistration registration =
                ClientRegistration.withRegistrationId("dingtalk")
                        .clientId("client-id")
                        .clientSecret("client-secret")
                        .authorizationGrantType(
                                AuthorizationGrantType.AUTHORIZATION_CODE)
                        .redirectUri(
                                "{baseUrl}/login/oauth2/code/{registrationId}")
                        .scope("openid")
                        .authorizationUri(authorizationUri)
                        .tokenUri(tokenUri)
                        .userInfoUri(userInfoUri)
                        .userNameAttributeName("dingtalkSubject")
                        .clientName("DingTalk")
                        .build();
        Instant issuedAt = Instant.parse("2026-08-03T00:00:00Z");
        OAuth2AccessToken token = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "token-123",
                issuedAt,
                issuedAt.plusSeconds(3600));
        return new OAuth2UserRequest(registration, token);
    }
}
