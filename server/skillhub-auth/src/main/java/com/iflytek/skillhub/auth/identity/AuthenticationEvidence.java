package com.iflytek.skillhub.auth.identity;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;

record AuthenticationEvidence(
        String protocol,
        Instant authenticatedAt,
        Set<String> authenticationMethods
) {
    AuthenticationEvidence {
        Objects.requireNonNull(protocol, "protocol");
        Objects.requireNonNull(authenticatedAt, "authenticatedAt");
        Objects.requireNonNull(authenticationMethods, "authenticationMethods");
        authenticationMethods = Set.copyOf(authenticationMethods);
    }
}
