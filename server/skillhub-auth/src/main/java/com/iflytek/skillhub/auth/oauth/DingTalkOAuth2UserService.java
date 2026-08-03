package com.iflytek.skillhub.auth.oauth;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

/**
 * Loads DingTalk user info using its non-standard access-token header.
 *
 * <p>This class only verifies protocol transport and returns upstream facts.
 * It does not create an account, principal, role or session.</p>
 */
@Component
public final class DingTalkOAuth2UserService
        implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private static final Duration MAX_TIMEOUT = Duration.ofMinutes(1);
    private static final int MIN_RESPONSE_BYTES = 1024;
    private static final int MAX_RESPONSE_BYTES = 1024 * 1024;
    private static final TypeReference<Map<String, Object>> RESPONSE_TYPE =
            new TypeReference<>() {
            };

    private final DingTalkProperties properties;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    @Autowired
    public DingTalkOAuth2UserService(
            DingTalkProperties properties,
            ObjectMapper objectMapper) {
        this(
                properties,
                objectMapper,
                buildRestTemplate(properties));
    }

    DingTalkOAuth2UserService(
            DingTalkProperties properties,
            ObjectMapper objectMapper,
            RestTemplate restTemplate) {
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.restTemplate = restTemplate;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest request) {
        requireTrustedRegistration(request);
        int maximumBytes = requireMaximumBytes();
        String responseBody;
        try {
            responseBody = restTemplate.execute(
                    DingTalkOAuth2Constants.USER_INFO_URI,
                    HttpMethod.GET,
                    httpRequest -> httpRequest.getHeaders().set(
                            DingTalkOAuth2Constants.ACCESS_TOKEN_HEADER,
                            request.getAccessToken().getTokenValue()),
                    response -> {
                        if (!response.getStatusCode().is2xxSuccessful()) {
                            throw failure("userinfo_response_rejected");
                        }
                        return readLimited(
                                response.getBody(),
                                maximumBytes);
                    });
        } catch (OAuth2AuthenticationException exception) {
            throw exception;
        } catch (RestClientException exception) {
            throw failure("userinfo_request_failed");
        }
        if (responseBody == null) {
            throw failure("userinfo_response_empty");
        }

        Map<String, Object> attributes;
        try {
            attributes = objectMapper.readValue(
                    responseBody,
                    RESPONSE_TYPE);
        } catch (IOException exception) {
            throw failure("userinfo_response_invalid");
        }
        String unionId = DingTalkClaimsExtractor.requireUnionId(attributes);
        Map<String, Object> copied = new HashMap<>(attributes);
        copied.put(DingTalkOAuth2Constants.SUBJECT_ATTRIBUTE, unionId);
        return new DefaultOAuth2User(
                Set.of(),
                copied,
                DingTalkOAuth2Constants.SUBJECT_ATTRIBUTE);
    }

    private void requireTrustedRegistration(OAuth2UserRequest request) {
        if (!properties.isEnabled()
                || request == null
                || !DingTalkOAuth2Constants.hasTrustedRegistration(
                        request.getClientRegistration())) {
            throw failure("dingtalk_provider_misconfigured");
        }
        if (request.getAccessToken() == null
                || request.getAccessToken().getTokenValue() == null
                || request.getAccessToken().getTokenValue().isBlank()) {
            throw failure("access_token_missing");
        }
        requireDuration(properties.getConnectTimeout());
        requireDuration(properties.getReadTimeout());
    }

    private int requireMaximumBytes() {
        int value = properties.getMaxResponseBytes();
        if (value < MIN_RESPONSE_BYTES || value > MAX_RESPONSE_BYTES) {
            throw failure("dingtalk_provider_misconfigured");
        }
        return value;
    }

    private void requireDuration(Duration value) {
        if (value == null
                || value.isZero()
                || value.isNegative()
                || value.compareTo(MAX_TIMEOUT) > 0) {
            throw failure("dingtalk_provider_misconfigured");
        }
    }

    private String readLimited(
            InputStream input,
            int maximumBytes) throws IOException {
        if (input == null) {
            throw failure("userinfo_response_empty");
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream(
                Math.min(maximumBytes, 8192));
        byte[] buffer = new byte[8192];
        int total = 0;
        int read;
        while ((read = input.read(buffer)) >= 0) {
            total += read;
            if (total > maximumBytes) {
                throw failure("userinfo_response_too_large");
            }
            output.write(buffer, 0, read);
        }
        return output.toString(StandardCharsets.UTF_8);
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
        return new OAuth2AuthenticationException(
                new OAuth2Error(errorCode));
    }
}
