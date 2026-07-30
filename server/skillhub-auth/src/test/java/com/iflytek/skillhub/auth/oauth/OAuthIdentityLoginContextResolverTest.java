package com.iflytek.skillhub.auth.oauth;

import static org.assertj.core.api.Assertions.assertThat;

import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

class OAuthIdentityLoginContextResolverTest {

    private final OAuthIdentityLoginContextResolver resolver =
            new OAuthIdentityLoginContextResolver();

    @AfterEach
    void clearRequestContext() {
        RequestContextHolder.resetRequestAttributes();
        MDC.clear();
    }

    @Test
    void extractsCallbackRequestAuditMetadata() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("203.0.113.9");
        request.addHeader("User-Agent", "SkillHub Browser");
        RequestContextHolder.setRequestAttributes(
                new ServletRequestAttributes(request));
        MDC.put("requestId", "req-123");

        IdentityLoginContext context = resolver.current();

        assertThat(context).isEqualTo(new IdentityLoginContext(
                "req-123",
                "203.0.113.9",
                "SkillHub Browser"));
    }

    @Test
    void dropsOversizedUntrustedHeadersInsteadOfFailingLogin() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("203.0.113.9");
        request.addHeader("User-Agent", "a".repeat(513));
        RequestContextHolder.setRequestAttributes(
                new ServletRequestAttributes(request));
        MDC.put("requestId", "r".repeat(65));

        IdentityLoginContext context = resolver.current();

        assertThat(context.requestId()).isNull();
        assertThat(context.clientIp()).isEqualTo("203.0.113.9");
        assertThat(context.userAgent()).isNull();
    }
}
