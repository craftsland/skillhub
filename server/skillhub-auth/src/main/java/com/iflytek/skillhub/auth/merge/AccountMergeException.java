package com.iflytek.skillhub.auth.merge;

import com.iflytek.skillhub.auth.exception.AuthFlowException;

/**
 * Account-merge failure carrying a stable reason code.
 */
public final class AccountMergeException extends AuthFlowException {

    private final AccountMergeFailureCode reasonCode;

    public AccountMergeException(
            AccountMergeFailureCode reasonCode) {
        this(reasonCode, null);
    }

    public AccountMergeException(
            AccountMergeFailureCode reasonCode,
            Throwable cause) {
        super(reasonCode.status(), reasonCode.messageCode());
        this.reasonCode = reasonCode;
        if (cause != null) {
            initCause(cause);
        }
    }

    public AccountMergeFailureCode getReasonCode() {
        return reasonCode;
    }
}
