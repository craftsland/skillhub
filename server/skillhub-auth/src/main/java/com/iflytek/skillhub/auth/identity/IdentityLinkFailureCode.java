package com.iflytek.skillhub.auth.identity;

import org.springframework.http.HttpStatus;

public enum IdentityLinkFailureCode {
    INTENT_NOT_FOUND(
            HttpStatus.NOT_FOUND,
            "error.auth.identityLink.intentNotFound"),
    REAUTHENTICATION_REQUIRED(
            HttpStatus.UNAUTHORIZED,
            "error.auth.identityLink.reauthenticationRequired"),
    SESSION_MISMATCH(
            HttpStatus.FORBIDDEN,
            "error.auth.identityLink.sessionMismatch"),
    INTENT_EXPIRED(
            HttpStatus.GONE,
            "error.auth.identityLink.intentExpired"),
    ALREADY_CONSUMED(
            HttpStatus.CONFLICT,
            "error.auth.identityLink.alreadyConsumed"),
    ACTIVE_INTENT_EXISTS(
            HttpStatus.CONFLICT,
            "error.auth.identityLink.activeIntentExists"),
    ACCOUNT_NOT_ELIGIBLE(
            HttpStatus.CONFLICT,
            "error.auth.identityLink.accountNotEligible"),
    PROVIDER_UNAVAILABLE(
            HttpStatus.SERVICE_UNAVAILABLE,
            "error.auth.identityLink.providerUnavailable"),
    PROVIDER_AUTHENTICATION_FAILED(
            HttpStatus.UNAUTHORIZED,
            "error.auth.identityLink.providerAuthenticationFailed"),
    ALREADY_LINKED(
            HttpStatus.CONFLICT,
            "error.auth.identityLink.alreadyLinked"),
    IDENTITY_IN_USE(
            HttpStatus.CONFLICT,
            "error.auth.identityLink.identityInUse"),
    FINAL_LOGIN_METHOD(
            HttpStatus.CONFLICT,
            "error.auth.identityLink.finalLoginMethod"),
    INVALID_OPERATION(
            HttpStatus.BAD_REQUEST,
            "error.auth.identityLink.invalidOperation");

    private final HttpStatus status;
    private final String messageCode;

    IdentityLinkFailureCode(
            HttpStatus status,
            String messageCode) {
        this.status = status;
        this.messageCode = messageCode;
    }

    public HttpStatus status() {
        return status;
    }

    public String messageCode() {
        return messageCode;
    }
}
