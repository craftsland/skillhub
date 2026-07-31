package com.iflytek.skillhub.service;

import java.util.Objects;

/**
 * Browser-flow control exception that never carries a ticket, state, upstream
 * payload, or user identifier.
 */
public final class CasLoginFlowException extends RuntimeException {

    private final CasLoginFailure failure;

    public CasLoginFlowException(CasLoginFailure failure) {
        super(Objects.requireNonNull(failure, "failure").name());
        this.failure = failure;
    }

    public CasLoginFailure failure() {
        return failure;
    }
}
