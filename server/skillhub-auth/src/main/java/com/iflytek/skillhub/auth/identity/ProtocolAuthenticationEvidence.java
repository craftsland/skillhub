package com.iflytek.skillhub.auth.identity;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Non-secret authentication facts reported by a protocol adapter.
 */
public record ProtocolAuthenticationEvidence(
        String protocol,
        Instant authenticatedAt,
        Set<String> authenticationMethods
) {
    private static final Pattern CODE_PATTERN =
            Pattern.compile("[a-z][a-z0-9_-]{0,63}");

    public ProtocolAuthenticationEvidence {
        Objects.requireNonNull(protocol, "protocol");
        Objects.requireNonNull(authenticatedAt, "authenticatedAt");
        Objects.requireNonNull(authenticationMethods, "authenticationMethods");
        if (!CODE_PATTERN.matcher(protocol).matches()) {
            throw new IllegalArgumentException("Invalid protocol code");
        }
        authenticationMethods = Set.copyOf(authenticationMethods);
        if (authenticationMethods.size() > 16) {
            throw new IllegalArgumentException("Too many authentication methods");
        }
        for (String method : authenticationMethods) {
            if (method == null || !CODE_PATTERN.matcher(method).matches()) {
                throw new IllegalArgumentException("Invalid authentication method");
            }
        }
    }
}
