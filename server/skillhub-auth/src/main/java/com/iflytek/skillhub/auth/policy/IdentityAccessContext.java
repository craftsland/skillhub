package com.iflytek.skillhub.auth.policy;

import com.iflytek.skillhub.auth.identity.EmailAssurance;
import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
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
        IdentityLoginContext requestContext
) {
    public IdentityAccessContext {
        Objects.requireNonNull(providerCode, "providerCode");
        Objects.requireNonNull(subjectType, "subjectType");
        Objects.requireNonNull(subjectValue, "subjectValue");
        Objects.requireNonNull(email, "email");
        Objects.requireNonNull(emailAssurance, "emailAssurance");
        Objects.requireNonNull(requestContext, "requestContext");
    }
}
