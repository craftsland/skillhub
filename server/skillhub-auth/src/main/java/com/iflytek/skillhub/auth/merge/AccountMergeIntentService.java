package com.iflytek.skillhub.auth.merge;

import java.sql.SQLException;
import java.util.Objects;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

/**
 * Public facade for safe account-merge intent state.
 */
@Service
public class AccountMergeIntentService {

    private final AccountMergeProperties properties;
    private final AccountMergeIntentTransaction transaction;
    private final AccountMergeMetrics metrics;

    public AccountMergeIntentService(
            AccountMergeProperties properties,
            AccountMergeIntentTransaction transaction,
            AccountMergeMetrics metrics) {
        this.properties = properties;
        this.transaction = transaction;
        this.metrics = metrics;
    }

    public void requireAvailable() {
        if (!properties.isEnabled()) {
            throw new AccountMergeException(
                    AccountMergeFailureCode
                            .ACCOUNT_MERGE_UNAVAILABLE);
        }
    }

    public boolean isAvailable() {
        return properties.isEnabled();
    }

    public AccountMergeIntent createIntent(
            AccountMergeActor actor,
            UUID intentId) {
        requireAvailable();
        Objects.requireNonNull(actor, "actor");
        Objects.requireNonNull(intentId, "intentId");
        try {
            AccountMergeIntent intent =
                    transaction.createIntent(actor, intentId);
            metrics.record("intent", "created");
            return intent;
        } catch (DataIntegrityViolationException exception) {
            if (isUniqueConstraintViolation(exception)) {
                throw new AccountMergeException(
                        AccountMergeFailureCode.MERGE_CONFLICT,
                        exception);
            }
            throw exception;
        }
    }

    public AccountMergeIntent getIntent(
            AccountMergeActor actor,
            UUID intentId) {
        requireAvailable();
        return transaction.getIntent(actor, intentId);
    }

    public AccountMergeIntent recordSecondaryProof(
            AccountMergeActor actor,
            UUID intentId,
            String secondaryUserId,
            String method) {
        requireAvailable();
        Objects.requireNonNull(
                secondaryUserId,
                "secondaryUserId");
        try {
            AccountMergeIntent intent =
                    transaction.recordSecondaryProof(
                    actor,
                    intentId,
                    secondaryUserId,
                    method);
            metrics.record("proof", "secondary_success");
            return intent;
        } catch (DataIntegrityViolationException exception) {
            if (isUniqueConstraintViolation(exception)) {
                throw new AccountMergeException(
                        AccountMergeFailureCode.MERGE_CONFLICT,
                        exception);
            }
            throw exception;
        }
    }

    public AccountMergePreview preview(
            AccountMergeActor actor,
            UUID intentId) {
        requireAvailable();
        AccountMergePreview preview =
                transaction.preview(actor, intentId);
        metrics.record(
                "preview",
                preview.plan().confirmable()
                        ? "ready"
                        : "conflict");
        return preview;
    }

    public AccountMergeCompletion confirm(
            AccountMergeActor actor,
            UUID intentId,
            int previewVersion) {
        requireAvailable();
        if (previewVersion <= 0) {
            throw new AccountMergeException(
                    AccountMergeFailureCode
                            .MERGE_PREVIEW_STALE);
        }
        try {
            AccountMergeCompletion completion =
                    confirmWithSerializationRetry(
                            actor,
                            intentId,
                            previewVersion);
            metrics.record("confirm", "completed");
            return completion;
        } catch (DataIntegrityViolationException exception) {
            metrics.record("confirm", "conflict");
            throw new AccountMergeException(
                    AccountMergeFailureCode.MERGE_CONFLICT,
                    exception);
        } catch (AccountMergeException exception) {
            metrics.record(
                    "confirm",
                    exception.getReasonCode().name());
            throw exception;
        } catch (RuntimeException exception) {
            metrics.record("confirm", "rollback");
            throw exception;
        }
    }

    private AccountMergeCompletion
            confirmWithSerializationRetry(
                    AccountMergeActor actor,
                    UUID intentId,
                    int previewVersion) {
        try {
            return transaction.confirm(
                    actor,
                    intentId,
                    previewVersion);
        } catch (RuntimeException firstFailure) {
            if (!isSerializationFailure(firstFailure)) {
                throw firstFailure;
            }
            metrics.record(
                    "confirm",
                    "serialization_retry");
            try {
                return transaction.confirm(
                        actor,
                        intentId,
                        previewVersion);
            } catch (RuntimeException repeatedFailure) {
                if (!isSerializationFailure(
                        repeatedFailure)) {
                    throw repeatedFailure;
                }
                throw new AccountMergeException(
                        AccountMergeFailureCode.MERGE_CONFLICT,
                        repeatedFailure);
            }
        }
    }

    private boolean isSerializationFailure(Throwable failure) {
        Throwable current = failure;
        while (current != null) {
            if (current instanceof SQLException sqlException
                    && "40001".equals(
                            sqlException.getSQLState())) {
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

    public AccountMergeIntent cancel(
            AccountMergeActor actor,
            UUID intentId) {
        requireAvailable();
        AccountMergeIntent intent =
                transaction.cancel(actor, intentId);
        metrics.record("intent", "cancelled");
        return intent;
    }

    /**
     * Expires persisted intents even when the feature flag is disabled, so
     * rollback does not leave active security workflow state indefinitely.
     */
    public int expireDueIntents(int batchSize) {
        int expired = transaction.expireDueIntents(batchSize);
        for (int index = 0; index < expired; index++) {
            metrics.record("intent", "expired");
        }
        return expired;
    }

    private boolean isUniqueConstraintViolation(Throwable failure) {
        Throwable current = failure;
        while (current != null) {
            if (current instanceof SQLException sqlException
                    && "23505".equals(
                            sqlException.getSQLState())) {
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
