package com.iflytek.skillhub.auth.cas;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Verified CAS service response. It intentionally contains no service ticket,
 * raw response, platform identity, role, or session object.
 */
public record CasAuthenticationExchange(
        String principal,
        Map<String, List<String>> attributes,
        Instant authenticatedAt
) {
    public CasAuthenticationExchange {
        Objects.requireNonNull(principal, "principal");
        Objects.requireNonNull(attributes, "attributes");
        Objects.requireNonNull(authenticatedAt, "authenticatedAt");
        if (principal.isBlank()) {
            throw new IllegalArgumentException(
                    "CAS principal is required");
        }

        LinkedHashMap<String, List<String>> copied =
                new LinkedHashMap<>();
        attributes.forEach((key, values) -> {
            Objects.requireNonNull(key, "CAS attribute key");
            List<String> copiedValues = List.copyOf(values);
            if (copiedValues.stream().anyMatch(Objects::isNull)) {
                throw new IllegalArgumentException(
                        "CAS attribute values cannot contain null");
            }
            copied.put(key, copiedValues);
        });
        attributes = Map.copyOf(copied);
    }
}
