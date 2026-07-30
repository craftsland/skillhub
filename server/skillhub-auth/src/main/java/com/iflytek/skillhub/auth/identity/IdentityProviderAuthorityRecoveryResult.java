package com.iflytek.skillhub.auth.identity;

import java.util.Objects;

/**
 * Observable result of an idempotent same-authority recovery request.
 */
public record IdentityProviderAuthorityRecoveryResult(
        String providerCode,
        boolean recovered,
        String state
) {
    public IdentityProviderAuthorityRecoveryResult {
        Objects.requireNonNull(providerCode, "providerCode");
        Objects.requireNonNull(state, "state");
    }
}
