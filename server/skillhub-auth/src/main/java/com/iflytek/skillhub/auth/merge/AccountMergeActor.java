package com.iflytek.skillhub.auth.merge;

import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
import java.time.Instant;
import java.util.Objects;

/**
 * Server-owned primary-account and session proof for an account-merge intent.
 *
 * <p>The raw session nonce is intentionally omitted from {@link #toString()}.
 */
public final class AccountMergeActor {

    private final String userId;
    private final String authenticationProvider;
    private final String sessionNonce;
    private final String primaryProofMethod;
    private final Instant primaryProofAt;
    private final IdentityLoginContext auditContext;

    public AccountMergeActor(
            String userId,
            String authenticationProvider,
            String sessionNonce,
            String primaryProofMethod,
            Instant primaryProofAt,
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
        this.primaryProofMethod = requireText(
                primaryProofMethod,
                "primaryProofMethod",
                96);
        this.primaryProofAt = Objects.requireNonNull(
                primaryProofAt,
                "primaryProofAt");
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

    public String primaryProofMethod() {
        return primaryProofMethod;
    }

    public Instant primaryProofAt() {
        return primaryProofAt;
    }

    public IdentityLoginContext auditContext() {
        return auditContext;
    }

    @Override
    public String toString() {
        return "AccountMergeActor[userId="
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
                    "Invalid account merge actor " + fieldName);
        }
        return value;
    }
}
