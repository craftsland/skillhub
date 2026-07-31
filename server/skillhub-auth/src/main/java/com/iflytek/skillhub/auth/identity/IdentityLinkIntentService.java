package com.iflytek.skillhub.auth.identity;

import com.iflytek.skillhub.auth.entity.IdentityLinkRequestStatus;
import com.iflytek.skillhub.auth.local.LocalAuthService;
import java.sql.SQLException;
import java.util.Objects;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

/**
 * Public workflow facade for creating, inspecting, reauthenticating, and
 * consuming Identity Link intents.
 *
 * <p>Raw session nonces are supplied by the HTTP session boundary and are
 * never persisted by this service.
 */
@Service
public class IdentityLinkIntentService {

    private final IdentityLinkTransaction transaction;
    private final LocalAuthService localAuthService;

    IdentityLinkIntentService(
            IdentityLinkTransaction transaction,
            LocalAuthService localAuthService) {
        this.transaction = transaction;
        this.localAuthService = localAuthService;
    }

    public IdentityLinkIntent createLinkIntent(
            IdentityLinkActor actor,
            UUID intentId,
            String providerCode) {
        Objects.requireNonNull(actor, "actor");
        Objects.requireNonNull(intentId, "intentId");
        try {
            return transaction.createLinkIntent(
                    actor,
                    intentId,
                    providerCode);
        } catch (DataIntegrityViolationException exception) {
            if (isUniqueConstraintViolation(exception)) {
                throw new IdentityLinkException(
                        IdentityLinkFailureCode.ACTIVE_INTENT_EXISTS,
                        exception);
            }
            throw exception;
        }
    }

    public IdentityLinkIntent createUnlinkIntent(
            IdentityLinkActor actor,
            UUID intentId,
            long bindingId) {
        Objects.requireNonNull(actor, "actor");
        Objects.requireNonNull(intentId, "intentId");
        try {
            return transaction.createUnlinkIntent(
                    actor,
                    intentId,
                    bindingId);
        } catch (DataIntegrityViolationException exception) {
            if (isUniqueConstraintViolation(exception)) {
                throw new IdentityLinkException(
                        IdentityLinkFailureCode.ACTIVE_INTENT_EXISTS,
                        exception);
            }
            throw exception;
        }
    }

    public IdentityLinkIntent getIntent(
            IdentityLinkActor actor,
            UUID intentId) {
        return transaction.getIntent(actor, intentId);
    }

    public IdentityLinkIntent cancel(
            IdentityLinkActor actor,
            UUID intentId) {
        return transaction.cancel(actor, intentId);
    }

    public IdentityLinkIntent reauthenticateLocal(
            IdentityLinkActor actor,
            UUID intentId,
            String password) {
        IdentityLinkIntent intent = transaction.getIntent(
                actor,
                intentId);
        if (intent.status()
                != IdentityLinkRequestStatus.PENDING_REAUTHENTICATION) {
            throw new IdentityLinkException(
                    IdentityLinkFailureCode.ALREADY_CONSUMED);
        }
        localAuthService.reauthenticate(
                actor.userId(),
                password);
        return transaction.markLocalReauthenticated(
                actor,
                intentId);
    }

    public IdentityLinkIntent prepareExternalReauthentication(
            IdentityLinkActor actor,
            UUID intentId,
            String providerCode,
            IdentityProviderLoginMethodType methodType) {
        return transaction.prepareExternalReauthentication(
                actor,
                intentId,
                providerCode,
                methodType);
    }

    public IdentityLinkIntent prepareExternalLink(
            IdentityLinkActor actor,
            UUID intentId,
            IdentityProviderLoginMethodType methodType) {
        return transaction.prepareExternalLink(
                actor,
                intentId,
                methodType);
    }

    public IdentityLinkIntent completeUnlink(
            IdentityLinkActor actor,
            UUID intentId) {
        return transaction.completeUnlink(actor, intentId);
    }

    public IdentityLinkAccountState accountState(String userId) {
        return transaction.accountState(userId);
    }

    private boolean isUniqueConstraintViolation(Throwable failure) {
        Throwable current = failure;
        while (current != null) {
            if (current instanceof SQLException sqlException
                    && "23505".equals(sqlException.getSQLState())) {
                return true;
            }
            Throwable cause = current.getCause();
            if (cause == current) {
                break;
            }
            current = cause;
        }
        return false;
    }
}
