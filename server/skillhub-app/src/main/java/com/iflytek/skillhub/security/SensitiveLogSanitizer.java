package com.iflytek.skillhub.security;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Applies lightweight redaction rules before sensitive strings are written to logs.
 */
@Component
public class SensitiveLogSanitizer {

    private static final Set<String> SENSITIVE_KEYS = Set.of(
            "password", "passwd", "pwd", "token", "authorization", "cookie",
            "secret", "api_key", "apikey", "access_key", "refresh_token",
            "code", "ticket", "state");

    public String sanitizeRequestTarget(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String query = request.getQueryString();
        if (!StringUtils.hasText(query)) {
            return uri;
        }
        return uri + "?" + sanitizeQuery(query);
    }

    String sanitizeQuery(String query) {
        return Arrays.stream(query.split("&"))
                .map(this::sanitizeQueryPart)
                .collect(Collectors.joining("&"));
    }

    private String sanitizeQueryPart(String queryPart) {
        int idx = queryPart.indexOf('=');
        if (idx < 0) {
            return queryPart;
        }
        String key = queryPart.substring(0, idx);
        String normalizedKey;
        try {
            normalizedKey = URLDecoder.decode(
                            key,
                            StandardCharsets.UTF_8)
                    .trim()
                    .toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException exception) {
            return key + "=[REDACTED]";
        }
        if (SENSITIVE_KEYS.contains(normalizedKey)) {
            return key + "=[REDACTED]";
        }
        return queryPart;
    }
}
