package com.iflytek.skillhub.auth.ldap;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Bounded, non-secret directory facts returned after a successful user bind.
 */
record LdapAuthenticatedEntry(
        String subject,
        Map<String, List<String>> attributes,
        Instant authenticatedAt
) {
    LdapAuthenticatedEntry {
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(attributes, "attributes");
        Objects.requireNonNull(authenticatedAt, "authenticatedAt");
        if (subject.isBlank()) {
            throw new IllegalArgumentException(
                    "LDAP subject must not be blank");
        }
        LinkedHashMap<String, List<String>> copied =
                new LinkedHashMap<>();
        attributes.forEach((key, values) -> {
            Objects.requireNonNull(key, "LDAP attribute key");
            Objects.requireNonNull(values, "LDAP attribute values");
            List<String> copiedValues = List.copyOf(values);
            if (copiedValues.stream().anyMatch(Objects::isNull)) {
                throw new IllegalArgumentException(
                        "LDAP attribute values must not contain null");
            }
            copied.put(key, copiedValues);
        });
        attributes = Map.copyOf(copied);
    }
}
