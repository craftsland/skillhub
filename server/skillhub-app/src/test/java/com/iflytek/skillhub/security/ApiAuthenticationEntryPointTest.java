package com.iflytek.skillhub.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iflytek.skillhub.dto.ApiResponseFactory;
import com.iflytek.skillhub.observability.RequestIdAccessor;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Locale;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;

class ApiAuthenticationEntryPointTest {

    private final ObjectMapper objectMapper =
            new ObjectMapper().findAndRegisterModules();
    private ApiAuthenticationEntryPoint entryPoint;

    @BeforeEach
    void setUp() {
        ResourceBundleMessageSource messageSource =
                new ResourceBundleMessageSource();
        messageSource.setBasename("messages");
        messageSource.setDefaultEncoding("UTF-8");
        RequestIdAccessor requestIdAccessor = new RequestIdAccessor();
        entryPoint = new ApiAuthenticationEntryPoint(
                objectMapper,
                new ApiResponseFactory(
                        messageSource,
                        Clock.fixed(
                                Instant.parse(
                                        "2026-07-31T00:00:00Z"),
                                ZoneOffset.UTC),
                        requestIdAccessor),
                new SensitiveLogSanitizer(),
                requestIdAccessor);
        LocaleContextHolder.setLocale(Locale.ENGLISH);
    }

    @AfterEach
    void tearDown() {
        LocaleContextHolder.resetLocaleContext();
    }

    @Test
    void identityLinkRouteUsesStableReauthenticationReason()
            throws Exception {
        MockHttpServletRequest request =
                new MockHttpServletRequest(
                        "POST",
                        "/api/v1/auth/identity-link-intents/link");
        MockHttpServletResponse response =
                new MockHttpServletResponse();

        entryPoint.commence(
                request,
                response,
                new AuthenticationCredentialsNotFoundException(
                        "missing"));

        JsonNode body = objectMapper.readTree(
                response.getContentAsByteArray());
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(body.path("reasonCode").asText())
                .isEqualTo("REAUTHENTICATION_REQUIRED");
    }

    @Test
    void unrelatedApiRouteKeepsGenericEnvelope()
            throws Exception {
        MockHttpServletRequest request =
                new MockHttpServletRequest(
                        "GET",
                        "/api/v1/skills");
        MockHttpServletResponse response =
                new MockHttpServletResponse();

        entryPoint.commence(
                request,
                response,
                new AuthenticationCredentialsNotFoundException(
                        "missing"));

        JsonNode body = objectMapper.readTree(
                response.getContentAsByteArray());
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(body.has("reasonCode")).isFalse();
    }
}
