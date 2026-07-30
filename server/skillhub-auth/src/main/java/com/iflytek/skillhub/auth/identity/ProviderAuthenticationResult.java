package com.iflytek.skillhub.auth.identity;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Protocol-neutral output of a trusted authentication adapter.
 *
 * <p>This record intentionally has no provider code, authority, platform user
 * id, role, principal, session, token, ticket, cookie, or raw response field.
 * The identity core binds these facts to a trusted server-side descriptor.</p>
 */
public record ProviderAuthenticationResult(
        SubjectCandidate primarySubject,
        List<SubjectCandidate> alternateSubjects,
        Map<String, List<ProviderAttributeValue>> attributes,
        ProtocolAuthenticationEvidence evidence
) {
    private static final Pattern ATTRIBUTE_KEY_PATTERN =
            Pattern.compile("[A-Za-z][A-Za-z0-9_.:-]{0,127}");
    private static final Set<String> SENSITIVE_ATTRIBUTE_NAMES = Set.of(
            "token",
            "access_token",
            "refresh_token",
            "id_token",
            "password",
            "cookie",
            "ticket",
            "authorization",
            "credential",
            "secret",
            "raw_response");

    public ProviderAuthenticationResult {
        Objects.requireNonNull(primarySubject, "primarySubject");
        Objects.requireNonNull(alternateSubjects, "alternateSubjects");
        Objects.requireNonNull(attributes, "attributes");
        Objects.requireNonNull(evidence, "evidence");

        alternateSubjects = List.copyOf(alternateSubjects);
        LinkedHashMap<String, List<ProviderAttributeValue>> copied = new LinkedHashMap<>();
        attributes.forEach((key, values) -> {
            if (key == null || !ATTRIBUTE_KEY_PATTERN.matcher(key).matches()) {
                throw new IllegalArgumentException("Invalid provider attribute key");
            }
            if (isSensitiveAttribute(key)) {
                throw new IllegalArgumentException(
                        "Sensitive provider attributes are forbidden");
            }
            Objects.requireNonNull(values, "Provider attribute values");
            List<ProviderAttributeValue> copiedValues = List.copyOf(values);
            if (copiedValues.stream().anyMatch(Objects::isNull)) {
                throw new IllegalArgumentException("Provider attribute values must not contain null");
            }
            copied.put(key, copiedValues);
        });
        attributes = Map.copyOf(copied);
    }

    private static boolean isSensitiveAttribute(String key) {
        String normalized = key.toLowerCase(Locale.ROOT);
        if (SENSITIVE_ATTRIBUTE_NAMES.contains(normalized)) {
            return true;
        }
        for (String segment : normalized.split("[._:-]")) {
            if (SENSITIVE_ATTRIBUTE_NAMES.contains(segment)) {
                return true;
            }
        }
        return false;
    }
}
