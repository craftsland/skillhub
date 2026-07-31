package com.iflytek.skillhub.service;

import com.iflytek.skillhub.auth.exception.AuthFlowException;
import com.iflytek.skillhub.auth.identity.IdentityLinkException;
import com.iflytek.skillhub.auth.identity.IdentityLinkFailureCode;
import com.iflytek.skillhub.auth.merge.AccountMergeException;
import com.iflytek.skillhub.auth.merge.AccountMergeFailureCode;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationException;
import org.springframework.http.HttpStatus;

/**
 * Maps stable provider failures to public authentication responses without
 * exposing upstream details.
 */
final class ProviderAuthenticationFailureMapper {

    private ProviderAuthenticationFailureMapper() {
    }

    static AuthFlowException map(
            ProviderAuthenticationException exception) {
        return switch (exception.getReasonCode()) {
            case UPSTREAM_INVALID_CREDENTIALS,
                    REPLAY_DETECTED -> failure(
                    HttpStatus.UNAUTHORIZED,
                    "error.auth.external.invalidAssertion");
            case UPSTREAM_ACCESS_DENIED -> failure(
                    HttpStatus.FORBIDDEN,
                    "error.auth.external.accessDenied");
            case UPSTREAM_UNAVAILABLE,
                    UPSTREAM_MISCONFIGURED,
                    TLS_VALIDATION_FAILED,
                    UPSTREAM_INVALID_RESPONSE -> failure(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "error.auth.external.providerUnavailable");
        };
    }

    static IdentityLinkException mapIdentityLink(
            ProviderAuthenticationException exception) {
        IdentityLinkFailureCode reasonCode =
                switch (exception.getReasonCode()) {
                    case UPSTREAM_INVALID_CREDENTIALS,
                            UPSTREAM_ACCESS_DENIED,
                            REPLAY_DETECTED ->
                            IdentityLinkFailureCode
                                    .PROVIDER_AUTHENTICATION_FAILED;
                    case UPSTREAM_UNAVAILABLE,
                            UPSTREAM_MISCONFIGURED,
                            TLS_VALIDATION_FAILED,
                            UPSTREAM_INVALID_RESPONSE ->
                            IdentityLinkFailureCode.PROVIDER_UNAVAILABLE;
                };
        return new IdentityLinkException(reasonCode, exception);
    }

    static AccountMergeException mapAccountMerge(
            ProviderAuthenticationException exception) {
        AccountMergeFailureCode reasonCode =
                switch (exception.getReasonCode()) {
                    case UPSTREAM_INVALID_CREDENTIALS,
                            UPSTREAM_ACCESS_DENIED,
                            REPLAY_DETECTED ->
                            AccountMergeFailureCode
                                    .MERGE_PROVIDER_AUTHENTICATION_FAILED;
                    case UPSTREAM_UNAVAILABLE,
                            UPSTREAM_MISCONFIGURED,
                            TLS_VALIDATION_FAILED,
                            UPSTREAM_INVALID_RESPONSE ->
                            AccountMergeFailureCode
                                    .MERGE_PROVIDER_UNAVAILABLE;
                };
        return new AccountMergeException(reasonCode, exception);
    }

    private static AuthFlowException failure(
            HttpStatus status,
            String messageCode) {
        return new AuthFlowException(status, messageCode);
    }
}
