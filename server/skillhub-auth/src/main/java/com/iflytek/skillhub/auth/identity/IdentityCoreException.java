package com.iflytek.skillhub.auth.identity;

import java.util.Objects;

/**
 * Security-oriented identity failure carrying only a stable reason code.
 */
public class IdentityCoreException extends RuntimeException {
    private final IdentityFailureCode reasonCode;

    public IdentityCoreException(IdentityFailureCode reasonCode) {
        super(Objects.requireNonNull(reasonCode, "reasonCode").name());
        this.reasonCode = reasonCode;
    }

    public IdentityCoreException(IdentityFailureCode reasonCode, Throwable cause) {
        super(Objects.requireNonNull(reasonCode, "reasonCode").name(), cause);
        this.reasonCode = reasonCode;
    }

    public IdentityFailureCode getReasonCode() {
        return reasonCode;
    }
}
