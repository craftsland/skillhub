package com.iflytek.skillhub.service;

import com.iflytek.skillhub.auth.exception.AuthFlowException;
import com.iflytek.skillhub.auth.identity.ExternalIdentityLoginService;
import com.iflytek.skillhub.auth.identity.IdentityCoreException;
import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
import com.iflytek.skillhub.auth.identity.IdentityLoginOutcome;
import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;
import com.iflytek.skillhub.auth.identity.ResolvedProviderHandle;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

/**
 * Application boundary shared by credential and passive provider flows.
 */
@Service
class ProviderLoginAppService {

    private static final String REQUEST_ID_MDC_KEY = "requestId";

    private final ExternalIdentityLoginService identityLoginService;

    ProviderLoginAppService(
            ExternalIdentityLoginService identityLoginService) {
        this.identityLoginService = identityLoginService;
    }

    PlatformPrincipal authenticate(
            ResolvedProviderHandle provider,
            ProviderAuthenticationResult result,
            HttpServletRequest request) {
        try {
            IdentityLoginOutcome outcome = identityLoginService.authenticate(
                    provider,
                    result,
                    context(request));
            if (outcome
                    instanceof IdentityLoginOutcome.Authenticated authenticated) {
                return authenticated.principal();
            }
            if (outcome instanceof IdentityLoginOutcome.PendingApproval) {
                throw failure(
                        HttpStatus.FORBIDDEN,
                        "error.auth.external.accountPending");
            }
            throw failure(
                    HttpStatus.FORBIDDEN,
                    "error.auth.external.linkRequired");
        } catch (IdentityCoreException exception) {
            throw mapFailure(exception);
        }
    }

    private IdentityLoginContext context(HttpServletRequest request) {
        return new IdentityLoginContext(
                bounded(MDC.get(REQUEST_ID_MDC_KEY), 64),
                bounded(request.getRemoteAddr(), 64),
                bounded(request.getHeader("User-Agent"), 512));
    }

    private String bounded(String value, int maximum) {
        return value == null || value.length() > maximum
                ? null
                : value;
    }

    private AuthFlowException mapFailure(
            IdentityCoreException exception) {
        return switch (exception.getReasonCode()) {
            case PROVIDER_DISABLED -> failure(
                    HttpStatus.FORBIDDEN,
                    "error.auth.external.providerUnavailable");
            case PROVIDER_AUTHORITY_MISMATCH -> failure(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "error.auth.external.providerUnavailable");
            case INVALID_IDENTITY_ASSERTION,
                    IDENTITY_SUBJECT_MISSING,
                    IDENTITY_IDENTIFIER_CONFLICT -> failure(
                    HttpStatus.UNAUTHORIZED,
                    "error.auth.external.invalidAssertion");
            case ACCESS_DENIED,
                    ACCOUNT_DISABLED,
                    ACCOUNT_MERGED,
                    SYSTEM_ACCOUNT_FORBIDDEN -> failure(
                    HttpStatus.FORBIDDEN,
                    "error.auth.external.accessDenied");
            case ACCOUNT_PENDING -> failure(
                    HttpStatus.FORBIDDEN,
                    "error.auth.external.accountPending");
        };
    }

    private AuthFlowException failure(
            HttpStatus status,
            String messageCode) {
        return new AuthFlowException(status, messageCode);
    }
}
