package com.iflytek.skillhub.auth.identity;

import com.iflytek.skillhub.auth.exception.AuthFlowException;

public final class IdentityLinkException extends AuthFlowException {

    private final IdentityLinkFailureCode reasonCode;

    public IdentityLinkException(IdentityLinkFailureCode reasonCode) {
        this(reasonCode, null);
    }

    public IdentityLinkException(
            IdentityLinkFailureCode reasonCode,
            Throwable cause) {
        super(reasonCode.status(), reasonCode.messageCode());
        this.reasonCode = reasonCode;
        if (cause != null) {
            initCause(cause);
        }
    }

    public IdentityLinkFailureCode getReasonCode() {
        return reasonCode;
    }
}
