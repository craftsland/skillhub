package com.iflytek.skillhub.auth.policy;

import com.iflytek.skillhub.auth.identity.EmailAssurance;
import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
import com.iflytek.skillhub.domain.user.UserStatus;
import java.util.Objects;
import java.util.Optional;

/**
 * Protocol-neutral facts available to external-login access policies.
 */
public record IdentityAccessContext(
        String providerCode,
        String subjectType,
        String subjectValue,
        Optional<String> email,
        EmailAssurance emailAssurance,
        IdentityLoginContext requestContext,
        IdentityAccessKind accessKind,
        Optional<UserStatus> existingAccountStatus
) {
    public IdentityAccessContext {
        Objects.requireNonNull(providerCode, "providerCode");
        Objects.requireNonNull(subjectType, "subjectType");
        Objects.requireNonNull(subjectValue, "subjectValue");
        Objects.requireNonNull(email, "email");
        Objects.requireNonNull(emailAssurance, "emailAssurance");
        Objects.requireNonNull(requestContext, "requestContext");
        Objects.requireNonNull(accessKind, "accessKind");
        Objects.requireNonNull(
                existingAccountStatus,
                "existingAccountStatus");
        if (accessKind == IdentityAccessKind.NEW_IDENTITY
                && existingAccountStatus.isPresent()) {
            throw new IllegalArgumentException(
                    "New identity cannot have an existing account status");
        }
        if (accessKind == IdentityAccessKind.RETURNING_IDENTITY
                && existingAccountStatus.isEmpty()) {
            throw new IllegalArgumentException(
                    "Returning identity requires account status");
        }
    }

    public IdentityAccessContext(
            String providerCode,
            String subjectType,
            String subjectValue,
            Optional<String> email,
            EmailAssurance emailAssurance,
            IdentityLoginContext requestContext) {
        this(
                providerCode,
                subjectType,
                subjectValue,
                email,
                emailAssurance,
                requestContext,
                IdentityAccessKind.NEW_IDENTITY,
                Optional.empty());
    }
}
