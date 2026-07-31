package com.iflytek.skillhub.auth.merge;

import com.iflytek.skillhub.auth.identity.ExternalIdentityProof;
import com.iflytek.skillhub.auth.identity.ExternalIdentityProofService;
import com.iflytek.skillhub.auth.identity.IdentityCoreException;
import com.iflytek.skillhub.auth.identity.IdentityFailureCode;
import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;
import com.iflytek.skillhub.auth.identity.ResolvedProviderHandle;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import jakarta.servlet.http.HttpSession;
import java.util.Objects;
import java.util.UUID;
import org.springframework.stereotype.Service;

/**
 * Converts verified provider facts into primary or secondary account-merge
 * ownership proofs without provisioning or changing the current principal.
 */
@Service
public class AccountMergeProviderProofService {

    private final ExternalIdentityProofService identityProofService;
    private final AccountMergeIntentService intentService;
    private final AccountMergeSessionManager sessionManager;
    private final AccountMergeMetrics metrics;

    public AccountMergeProviderProofService(
            ExternalIdentityProofService identityProofService,
            AccountMergeIntentService intentService,
            AccountMergeSessionManager sessionManager,
            AccountMergeMetrics metrics) {
        this.identityProofService = identityProofService;
        this.intentService = intentService;
        this.sessionManager = sessionManager;
        this.metrics = metrics;
    }

    public AccountMergeProviderPrimaryProof completePrimary(
            HttpSession session,
            ResolvedProviderHandle provider,
            ProviderAuthenticationResult result,
            IdentityLoginContext context) {
        try {
            PlatformPrincipal primary = requirePrincipal(session);
            ExternalIdentityProof proof = authenticate(
                    provider,
                    result,
                    context);
            if (!primary.userId().equals(proof.userId())) {
                throw failure(
                        AccountMergeFailureCode
                                .MERGE_ACCOUNT_NOT_ELIGIBLE);
            }
            AccountMergePrimaryProof primaryProof =
                    sessionManager.recordPrimaryReauthentication(
                            session,
                            primary.userId(),
                            proofMethod(proof));
            metrics.recordProviderProof(
                    provider.providerCode(),
                    "primary",
                    "success");
            return new AccountMergeProviderPrimaryProof(
                    primary,
                    primaryProof);
        } catch (AccountMergeException exception) {
            metrics.recordProviderProof(
                    provider.providerCode(),
                    "primary",
                    exception.getReasonCode().name());
            throw exception;
        }
    }

    public AccountMergeIntent completeSecondary(
            AccountMergeActor actor,
            UUID intentId,
            ResolvedProviderHandle provider,
            ProviderAuthenticationResult result,
            IdentityLoginContext context) {
        try {
            ExternalIdentityProof proof = authenticate(
                    provider,
                    result,
                    context);
            AccountMergeIntent intent =
                    intentService.recordSecondaryProof(
                            actor,
                            intentId,
                            proof.userId(),
                            proofMethod(proof));
            metrics.recordProviderProof(
                    provider.providerCode(),
                    "secondary",
                    "success");
            return intent;
        } catch (AccountMergeException exception) {
            metrics.recordProviderProof(
                    provider.providerCode(),
                    "secondary",
                    exception.getReasonCode().name());
            throw exception;
        }
    }

    private ExternalIdentityProof authenticate(
            ResolvedProviderHandle provider,
            ProviderAuthenticationResult result,
            IdentityLoginContext context) {
        try {
            return identityProofService.authenticateExisting(
                    Objects.requireNonNull(provider, "provider"),
                    Objects.requireNonNull(result, "result"),
                    Objects.requireNonNull(context, "context"));
        } catch (IdentityCoreException exception) {
            throw failure(
                    map(exception.getReasonCode()),
                    exception);
        }
    }

    private AccountMergeFailureCode map(
            IdentityFailureCode reasonCode) {
        return switch (reasonCode) {
            case PROVIDER_DISABLED,
                    PROVIDER_AUTHORITY_MISMATCH ->
                    AccountMergeFailureCode
                            .MERGE_PROVIDER_UNAVAILABLE;
            case INVALID_IDENTITY_ASSERTION,
                    IDENTITY_SUBJECT_MISSING,
                    IDENTITY_IDENTIFIER_CONFLICT ->
                    AccountMergeFailureCode
                            .MERGE_PROVIDER_AUTHENTICATION_FAILED;
            case ACCESS_DENIED,
                    ACCOUNT_PENDING,
                    ACCOUNT_DISABLED,
                    ACCOUNT_MERGED,
                    SYSTEM_ACCOUNT_FORBIDDEN ->
                    AccountMergeFailureCode
                            .MERGE_ACCOUNT_NOT_ELIGIBLE;
        };
    }

    private String proofMethod(ExternalIdentityProof proof) {
        return "provider:" + proof.providerCode();
    }

    private PlatformPrincipal requirePrincipal(
            HttpSession session) {
        Object value = session == null
                ? null
                : session.getAttribute("platformPrincipal");
        if (!(value instanceof PlatformPrincipal principal)) {
            throw failure(
                    AccountMergeFailureCode
                            .MERGE_SESSION_MISMATCH);
        }
        return principal;
    }

    private AccountMergeException failure(
            AccountMergeFailureCode code) {
        return new AccountMergeException(code);
    }

    private AccountMergeException failure(
            AccountMergeFailureCode code,
            RuntimeException cause) {
        return new AccountMergeException(code, cause);
    }
}
