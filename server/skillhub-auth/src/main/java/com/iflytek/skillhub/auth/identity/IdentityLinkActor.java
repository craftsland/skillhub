package com.iflytek.skillhub.auth.identity;

import java.util.Objects;

/**
 * Server-owned account and session proof used by Identity Link workflows.
 *
 * <p>The raw session nonce is intentionally omitted from {@link #toString()}.
 */
public final class IdentityLinkActor {

    private final String userId;
    private final String authenticationProvider;
    private final String sessionNonce;
    private final IdentityLoginContext auditContext;

    public IdentityLinkActor(
            String userId,
            String authenticationProvider,
            String sessionNonce,
            IdentityLoginContext auditContext) {
        this.userId = requireText(userId, "userId", 128);
        this.authenticationProvider = requireText(
                authenticationProvider,
                "authenticationProvider",
                64);
        this.sessionNonce = requireText(
                sessionNonce,
                "sessionNonce",
                256);
        this.auditContext = Objects.requireNonNull(
                auditContext,
                "auditContext");
    }

    public String userId() {
        return userId;
    }

    String authenticationProvider() {
        return authenticationProvider;
    }

    String sessionNonce() {
        return sessionNonce;
    }

    public IdentityLoginContext auditContext() {
        return auditContext;
    }

    @Override
    public String toString() {
        return "IdentityLinkActor[userId="
                + userId
                + ", authenticationProvider="
                + authenticationProvider
                + "]";
    }

    private static String requireText(
            String value,
            String fieldName,
            int maximumLength) {
        if (value == null
                || value.isBlank()
                || value.length() > maximumLength) {
            throw new IllegalArgumentException(
                    "Invalid identity link actor " + fieldName);
        }
        return value;
    }
}
