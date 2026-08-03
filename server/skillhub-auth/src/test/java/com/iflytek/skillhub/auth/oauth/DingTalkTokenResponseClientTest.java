package com.iflytek.skillhub.auth.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

class DingTalkTokenResponseClientTest {

    @Test
    void exchangesAuthorizationCodeAsDingTalkJsonAndValidatesExpiry() {
        DingTalkProperties properties = enabledProperties();
        RestTemplate restTemplate = new RestTemplate();
        MockRestServiceServer server =
                MockRestServiceServer.bindTo(restTemplate).build();
        server.expect(requestTo(DingTalkOAuth2Constants.TOKEN_URI))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header(
                        HttpHeaders.CONTENT_TYPE,
                        MediaType.APPLICATION_JSON_VALUE))
                .andExpect(content().json(
                        """
                        {
                          "clientId":"client-id",
                          "clientSecret":"client-secret",
                          "code":"code-123",
                          "grantType":"authorization_code"
                        }
                        """))
                .andRespond(withSuccess(
                        "{\"accessToken\":\"access-123\",\"expireIn\":3600}",
                        MediaType.APPLICATION_JSON));

        OAuth2AccessTokenResponse response = new DingTalkTokenResponseClient(
                properties,
                new com.fasterxml.jackson.databind.ObjectMapper(),
                restTemplate).getTokenResponse(request("code-123"));

        assertThat(response.getAccessToken().getTokenValue())
                .isEqualTo("access-123");
        assertThat(response.getAccessToken().getExpiresAt())
                .isAfter(Instant.now());
        assertThat(response.getAdditionalParameters())
                .containsEntry("expireIn", 3600L);
        server.verify();
    }

    @Test
    void rejectsNonPositiveOrUnreasonablyLongExpiry() {
        DingTalkProperties properties = enabledProperties();
        RestTemplate restTemplate = new RestTemplate();
        MockRestServiceServer server =
                MockRestServiceServer.bindTo(restTemplate).build();
        server.expect(requestTo(DingTalkOAuth2Constants.TOKEN_URI))
                .andRespond(withSuccess(
                        "{\"accessToken\":\"access-123\",\"expireIn\":0}",
                        MediaType.APPLICATION_JSON));

        assertThatThrownBy(() -> new DingTalkTokenResponseClient(
                properties,
                new com.fasterxml.jackson.databind.ObjectMapper(),
                restTemplate).getTokenResponse(request("code-123")))
                .isInstanceOfSatisfying(
                        OAuth2AuthenticationException.class,
                        exception -> assertThat(
                                exception.getError().getErrorCode())
                                .isEqualTo("token_response_invalid"));
        server.verify();
    }

    @Test
    void rejectsOversizedTokenResponseWithoutIncludingResponseBodyInError() {
        DingTalkProperties properties = enabledProperties();
        properties.setMaxResponseBytes(1024);
        RestTemplate restTemplate = new RestTemplate();
        MockRestServiceServer server =
                MockRestServiceServer.bindTo(restTemplate).build();
        server.expect(requestTo(DingTalkOAuth2Constants.TOKEN_URI))
                .andRespond(withSuccess(
                        "{\"accessToken\":\"access-123\",\"padding\":\""
                                + "x".repeat(1100) + "\"}",
                        MediaType.APPLICATION_JSON));

        assertThatThrownBy(() -> new DingTalkTokenResponseClient(
                properties,
                new com.fasterxml.jackson.databind.ObjectMapper(),
                restTemplate).getTokenResponse(request("code-123")))
                .isInstanceOfSatisfying(
                        OAuth2AuthenticationException.class,
                        exception -> {
                            assertThat(exception.getError().getErrorCode())
                                    .isEqualTo("token_response_too_large");
                            assertThat(exception.toString())
                                    .doesNotContain("access-123")
                                    .doesNotContain("padding");
                        });
        server.verify();
    }

    @Test
    void rejectsIncompleteClientCredentialsBeforeMakingTokenRequest() {
        DingTalkProperties properties = enabledProperties();
        RestTemplate restTemplate = new RestTemplate();
        MockRestServiceServer server =
                MockRestServiceServer.bindTo(restTemplate).build();

        assertThatThrownBy(() -> new DingTalkTokenResponseClient(
                properties,
                new com.fasterxml.jackson.databind.ObjectMapper(),
                restTemplate).getTokenResponse(
                        request("code-123", "client-id", "")))
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

    private static OAuth2AuthorizationCodeGrantRequest request(String code) {
        return request(code, "client-id", "client-secret");
    }

    private static OAuth2AuthorizationCodeGrantRequest request(
            String code,
            String clientId,
            String clientSecret) {
        ClientRegistration registration =
                ClientRegistration.withRegistrationId("dingtalk")
                        .clientId(clientId)
                        .clientSecret(clientSecret)
                        .authorizationGrantType(
                                AuthorizationGrantType.AUTHORIZATION_CODE)
                        .redirectUri(
                                "{baseUrl}/login/oauth2/code/{registrationId}")
                        .scope("openid")
                        .authorizationUri(
                                DingTalkOAuth2Constants.AUTHORIZATION_URI)
                        .tokenUri(DingTalkOAuth2Constants.TOKEN_URI)
                        .userInfoUri(
                                DingTalkOAuth2Constants.USER_INFO_URI)
                        .userNameAttributeName(
                                DingTalkOAuth2Constants.SUBJECT_ATTRIBUTE)
                        .clientName("DingTalk")
                        .build();
        OAuth2AuthorizationRequest authorizationRequest =
                OAuth2AuthorizationRequest.authorizationCode()
                        .authorizationUri(
                                DingTalkOAuth2Constants.AUTHORIZATION_URI)
                        .clientId("client-id")
                        .redirectUri(
                                "https://skillhub.example/login/oauth2/code/dingtalk")
                        .scope(DingTalkOAuth2Constants.AUTHORIZATION_SCOPE)
                        .state("state-123")
                        .build();
        OAuth2AuthorizationResponse authorizationResponse =
                OAuth2AuthorizationResponse.success(code)
                        .redirectUri(
                                "https://skillhub.example/login/oauth2/code/dingtalk")
                        .state("state-123")
                        .build();
        return new OAuth2AuthorizationCodeGrantRequest(
                registration,
                new OAuth2AuthorizationExchange(
                        authorizationRequest,
                        authorizationResponse));
    }
}
