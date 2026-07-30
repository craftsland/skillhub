package com.iflytek.skillhub.auth.provider;

import java.util.Objects;

/**
 * Authentication-adapter failure carrying only a stable reason code.
 *
 * <p>Adapters must not put credentials, tokens, tickets, cookies, upstream
 * payloads or user identifiers in the exception message.</p>
 */
public final class ProviderAuthenticationException
        extends RuntimeException {

    private final ProviderAuthenticationFailureCode reasonCode;

    public ProviderAuthenticationException(
            ProviderAuthenticationFailureCode reasonCode) {
        super(Objects.requireNonNull(reasonCode, "reasonCode").name());
        this.reasonCode = reasonCode;
    }

    public ProviderAuthenticationException(
            ProviderAuthenticationFailureCode reasonCode,
            Throwable cause) {
        super(
                Objects.requireNonNull(reasonCode, "reasonCode").name(),
                cause);
        this.reasonCode = reasonCode;
    }

    public ProviderAuthenticationFailureCode getReasonCode() {
        return reasonCode;
    }
}
