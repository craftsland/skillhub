package com.iflytek.skillhub.auth.merge;

import org.springframework.http.HttpStatus;

/**
 * Stable machine-readable failures for the safe account-merge workflow.
 */
public enum AccountMergeFailureCode {
    ACCOUNT_MERGE_UNAVAILABLE(
            HttpStatus.SERVICE_UNAVAILABLE,
            "error.auth.accountMerge.unavailable"),
    MERGE_INTENT_NOT_FOUND(
            HttpStatus.NOT_FOUND,
            "error.auth.accountMerge.intentNotFound"),
    MERGE_REAUTH_REQUIRED(
            HttpStatus.UNAUTHORIZED,
            "error.auth.accountMerge.reauthenticationRequired"),
    MERGE_PROVIDER_AUTHENTICATION_FAILED(
            HttpStatus.UNAUTHORIZED,
            "error.auth.accountMerge.providerAuthenticationFailed"),
    MERGE_PROVIDER_UNAVAILABLE(
            HttpStatus.SERVICE_UNAVAILABLE,
            "error.auth.accountMerge.providerUnavailable"),
    MERGE_SESSION_MISMATCH(
            HttpStatus.FORBIDDEN,
            "error.auth.accountMerge.sessionMismatch"),
    MERGE_PROOF_EXPIRED(
            HttpStatus.GONE,
            "error.auth.accountMerge.proofExpired"),
    MERGE_CONFLICT(
            HttpStatus.CONFLICT,
            "error.auth.accountMerge.conflict"),
    MERGE_PREVIEW_STALE(
            HttpStatus.CONFLICT,
            "error.auth.accountMerge.previewStale"),
    MERGE_ALREADY_CONSUMED(
            HttpStatus.CONFLICT,
            "error.auth.accountMerge.alreadyConsumed"),
    MERGE_ACCOUNT_NOT_ELIGIBLE(
            HttpStatus.CONFLICT,
            "error.auth.accountMerge.accountNotEligible");

    private final HttpStatus status;
    private final String messageCode;

    AccountMergeFailureCode(
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
