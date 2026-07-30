package com.iflytek.skillhub.auth.provider;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable, servlet-independent input for passive authentication adapters.
 *
 * <p>Header and query values can contain credentials and must not be logged or
 * retained. The application layer creates this snapshot without exposing the
 * HTTP session or Spring Security context to an adapter.</p>
 */
public record PassiveAuthenticationRequest(
        String method,
        String requestUri,
        String queryString,
        String remoteAddress,
        Map<String, List<String>> headers
) {

    public PassiveAuthenticationRequest {
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(requestUri, "requestUri");
        Objects.requireNonNull(headers, "headers");
        if (method.isBlank()) {
            throw new IllegalArgumentException("HTTP method is required");
        }
        if (requestUri.isBlank()) {
            throw new IllegalArgumentException("Request URI is required");
        }

        method = method.toUpperCase(Locale.ROOT);
        LinkedHashMap<String, List<String>> copied =
                new LinkedHashMap<>();
        headers.forEach((name, values) -> {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException(
                        "HTTP header name is required");
            }
            Objects.requireNonNull(values, "HTTP header values");
            List<String> copiedValues = List.copyOf(values);
            String normalizedName = name.toLowerCase(Locale.ROOT);
            copied.merge(
                    normalizedName,
                    copiedValues,
                    PassiveAuthenticationRequest::merge);
        });
        headers = Collections.unmodifiableMap(copied);
    }

    /**
     * Returns an immutable, case-insensitive header lookup result.
     */
    public List<String> headerValues(String name) {
        Objects.requireNonNull(name, "name");
        return headers.getOrDefault(
                name.toLowerCase(Locale.ROOT),
                List.of());
    }

    /**
     * Returns the first header value, or {@code null} when absent.
     */
    public String firstHeader(String name) {
        List<String> values = headerValues(name);
        return values.isEmpty() ? null : values.getFirst();
    }

    private static List<String> merge(
            List<String> existing,
            List<String> additional) {
        ArrayList<String> merged = new ArrayList<>(
                existing.size() + additional.size());
        merged.addAll(existing);
        merged.addAll(additional);
        return List.copyOf(merged);
    }
}
