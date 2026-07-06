package com.iflytek.skillhub.compat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClawHubRegistrySecurityConfigTest {

    @Test
    void publicLabelMatcherOnlyMatchesGetRequests() {
        RequestMatcher matcher = ClawHubRegistrySecurityConfig.publicLabelRequestMatcher();

        assertTrue(matcher.matches(request("GET", "/api/v1/labels")));
        assertTrue(matcher.matches(request("GET", "/api/web/labels")));
        assertFalse(matcher.matches(request("POST", "/api/v1/labels")));
        assertFalse(matcher.matches(request("POST", "/api/web/labels")));
    }

    private MockHttpServletRequest request(String method, String path) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        request.setServletPath(path);
        return request;
    }
}
