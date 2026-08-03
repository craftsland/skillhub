package com.iflytek.skillhub.auth.oauth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

/** Adapts DingTalk's JSON authorization-code token exchange. */
@Component
public final class DingTalkTokenResponseClient
        implements OAuth2AccessTokenResponseClient<
                OAuth2AuthorizationCodeGrantRequest> {

    private static final Duration MAX_TIMEOUT = Duration.ofMinutes(1);
    private static final int MIN_RESPONSE_BYTES = 1024;
    private static final int MAX_RESPONSE_BYTES = 1024 * 1024;
    private static final long MAX_TOKEN_LIFETIME_SECONDS = 86_400L;

    private final DingTalkProperties properties;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    @Autowired
    public DingTalkTokenResponseClient(
            DingTalkProperties properties,
            ObjectMapper objectMapper) {
        this(
                properties,
                objectMapper,
                buildRestTemplate(properties));
    }

    DingTalkTokenResponseClient(
            DingTalkProperties properties,
            ObjectMapper objectMapper,
            RestTemplate restTemplate) {
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.restTemplate = restTemplate;
    }

    @Override
    public OAuth2AccessTokenResponse getTokenResponse(
            OAuth2AuthorizationCodeGrantRequest request) {
        if (request == null
                || !properties.isEnabled()
                || !DingTalkOAuth2Constants.hasTrustedRegistration(
                        request.getClientRegistration())
                || !hasRealClientCredentials(request)) {
            throw failure("dingtalk_provider_misconfigured");
        }
        requireDuration(properties.getConnectTimeout());
        requireDuration(properties.getReadTimeout());
        int maximumBytes = requireMaximumBytes();
        String code = request.getAuthorizationExchange() == null
                || request.getAuthorizationExchange()
                        .getAuthorizationResponse() == null
                ? null
                : request.getAuthorizationExchange()
                        .getAuthorizationResponse()
                        .getCode();
        if (code == null || code.isBlank()) {
            throw failure("authorization_code_missing");
        }

        Map<String, String> body = Map.of(
                "clientId",
                request.getClientRegistration().getClientId(),
                "clientSecret",
                request.getClientRegistration().getClientSecret(),
                "code",
                code,
                "grantType",
                "authorization_code");
        String responseBody;
        try {
            responseBody = restTemplate.execute(
                    DingTalkOAuth2Constants.TOKEN_URI,
                    HttpMethod.POST,
                    httpRequest -> {
                        httpRequest.getHeaders().setContentType(
                                MediaType.APPLICATION_JSON);
                        byte[] encoded = objectMapper.writeValueAsBytes(body);
                        httpRequest.getBody().write(encoded);
                    },
                    response -> {
                        if (!response.getStatusCode().is2xxSuccessful()) {
                            throw failure("token_response_rejected");
                        }
                        return readLimited(response.getBody(), maximumBytes);
                    });
        } catch (OAuth2AuthenticationException exception) {
            throw exception;
        } catch (RestClientException exception) {
            throw failure("token_request_failed");
        }
        if (responseBody == null) {
            throw failure("token_response_empty");
        }

        JsonNode response;
        try {
            response = objectMapper.readTree(responseBody);
        } catch (JsonProcessingException exception) {
            throw failure("token_response_invalid");
        }
        String accessToken = text(response, "accessToken");
        JsonNode expires = response.get("expireIn");
        if (accessToken == null
                || expires == null
                || !expires.isIntegralNumber()
                || !expires.canConvertToLong()) {
            throw failure("token_response_invalid");
        }
        long lifetime = expires.longValue();
        if (lifetime <= 0 || lifetime > MAX_TOKEN_LIFETIME_SECONDS) {
            throw failure("token_response_invalid");
        }
        return OAuth2AccessTokenResponse.withToken(accessToken)
                .tokenType(TokenType.BEARER)
                .expiresIn(lifetime)
                .additionalParameters(Map.of("expireIn", lifetime))
                .build();
    }

    private String text(JsonNode object, String field) {
        JsonNode value = object == null ? null : object.get(field);
        if (value == null || !value.isTextual() || value.textValue().isBlank()) {
            return null;
        }
        return value.textValue();
    }

    private String readLimited(InputStream input, int maximumBytes)
            throws IOException {
        if (input == null) {
            throw failure("token_response_empty");
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream(
                Math.min(maximumBytes, 8192));
        byte[] buffer = new byte[8192];
        int total = 0;
        int read;
        while ((read = input.read(buffer)) >= 0) {
            total += read;
            if (total > maximumBytes) {
                throw failure("token_response_too_large");
            }
            output.write(buffer, 0, read);
        }
        return output.toString(StandardCharsets.UTF_8);
    }

    private int requireMaximumBytes() {
        int value = properties.getMaxResponseBytes();
        if (value < MIN_RESPONSE_BYTES || value > MAX_RESPONSE_BYTES) {
            throw failure("dingtalk_provider_misconfigured");
        }
        return value;
    }

    private boolean hasRealClientCredentials(
            OAuth2AuthorizationCodeGrantRequest request) {
        String clientId = request.getClientRegistration().getClientId();
        String clientSecret = request.getClientRegistration().getClientSecret();
        return isRealCredential(clientId) && isRealCredential(clientSecret);
    }

    private boolean isRealCredential(String value) {
        return value != null
                && !value.isBlank()
                && !value.toLowerCase(java.util.Locale.ROOT)
                        .contains("placeholder");
    }

    private void requireDuration(Duration value) {
        if (value == null
                || value.isZero()
                || value.isNegative()
                || value.compareTo(MAX_TIMEOUT) > 0) {
            throw failure("dingtalk_provider_misconfigured");
        }
    }

    private static RestTemplate buildRestTemplate(
            DingTalkProperties properties) {
        SimpleClientHttpRequestFactory factory =
                new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(properties.getConnectTimeout());
        factory.setReadTimeout(properties.getReadTimeout());
        return new RestTemplate(factory);
    }

    private OAuth2AuthenticationException failure(String errorCode) {
        return new OAuth2AuthenticationException(new OAuth2Error(errorCode));
    }
}
