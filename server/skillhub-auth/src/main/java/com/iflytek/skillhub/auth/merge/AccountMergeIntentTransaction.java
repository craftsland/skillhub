package com.iflytek.skillhub.auth.merge;

import com.iflytek.skillhub.auth.identity.AccountLoginDecision;
import com.iflytek.skillhub.auth.identity.AccountLoginGuard;
import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
import com.iflytek.skillhub.domain.audit.AuditLogService;
import com.iflytek.skillhub.domain.user.UserAccount;
import com.iflytek.skillhub.domain.user.UserAccountRepository;
import com.iflytek.skillhub.domain.user.UserStatus;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.data.domain.PageRequest;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Short PostgreSQL transaction for creating account-merge intents.
 */
@Service
class AccountMergeIntentTransaction {

    static final Duration INTENT_TTL = Duration.ofMinutes(10);

    private static final Set<AccountMergeIntentStatus>
            ACTIVE_STATUSES = Set.of(
                    AccountMergeIntentStatus
                            .PENDING_SECONDARY_PROOF,
                    AccountMergeIntentStatus
                            .READY_FOR_PREVIEW,
                    AccountMergeIntentStatus
                            .READY_TO_CONFIRM,
                    AccountMergeIntentStatus
                            .FAILED_CONFLICT);

    private final AccountMergeIntentRepository intentRepository;
    private final UserAccountRepository userRepository;
    private final AccountLoginGuard accountLoginGuard;
    private final AccountMergeStateHasher stateHasher;
    private final AccountMergeDataGateway dataGateway;
    private final AuditLogService auditLogService;
    private final Clock clock;

    AccountMergeIntentTransaction(
            AccountMergeIntentRepository intentRepository,
            UserAccountRepository userRepository,
            AccountLoginGuard accountLoginGuard,
            AccountMergeStateHasher stateHasher,
            AccountMergeDataGateway dataGateway,
            AuditLogService auditLogService,
            Clock clock) {
        this.intentRepository = intentRepository;
        this.userRepository = userRepository;
        this.accountLoginGuard = accountLoginGuard;
        this.stateHasher = stateHasher;
        this.dataGateway = dataGateway;
        this.auditLogService = auditLogService;
        this.clock = clock;
    }

    @Transactional(noRollbackFor = AccountMergeException.class)
    public AccountMergeIntent createIntent(
            AccountMergeActor actor,
            UUID intentId) {
        Instant now = now();
        requireEligiblePrimary(actor.userId());
        if (!now.isBefore(actor.primaryProofAt()
                .plus(AccountMergeSessionManager
                        .PRIMARY_PROOF_TTL))) {
            throw failure(
                    AccountMergeFailureCode
                            .MERGE_PROOF_EXPIRED);
        }
        expireExistingIntent(actor, now);
        AccountMergeIntentEntity intent =
                new AccountMergeIntentEntity(
                        intentId,
                        actor.userId(),
                        stateHasher.hash(
                                actor.sessionNonce()),
                        actor.primaryProofMethod(),
                        actor.primaryProofAt(),
                        earliest(
                                now.plus(INTENT_TTL),
                                actor.primaryProofAt().plus(
                                        AccountMergeSessionManager
                                                .PRIMARY_PROOF_TTL)),
                        now);
        intentRepository.saveAndFlush(intent);
        recordAudit(
                actor,
                "ACCOUNT_MERGE_PRIMARY_REAUTHENTICATED",
                intent,
                actor.primaryProofMethod());
        recordAudit(
                actor,
                "ACCOUNT_MERGE_INTENT_CREATED",
                intent,
                "pending_secondary_proof");
        return toIntent(intent);
    }

    @Transactional(noRollbackFor = AccountMergeException.class)
    public AccountMergeIntent getIntent(
            AccountMergeActor actor,
            UUID intentId) {
        return toIntent(requireActiveIntent(
                actor,
                intentId));
    }

    @Transactional(noRollbackFor = AccountMergeException.class)
    public AccountMergeIntent recordSecondaryProof(
            AccountMergeActor actor,
            UUID intentId,
            String secondaryUserId,
            String method) {
        AccountMergeIntentEntity intent =
                requireActiveIntent(actor, intentId);
        if (intent.getStatus()
                != AccountMergeIntentStatus
                        .PENDING_SECONDARY_PROOF) {
            throw failure(
                    AccountMergeFailureCode
                            .MERGE_ALREADY_CONSUMED);
        }
        if (actor.userId().equals(secondaryUserId)) {
            throw failure(
                    AccountMergeFailureCode
                            .MERGE_ACCOUNT_NOT_ELIGIBLE);
        }
        lockEligibleAccounts(
                actor.userId(),
                secondaryUserId);
        boolean secondaryAlreadyParticipates =
                intentRepository
                        .findActiveByParticipantForUpdate(
                                secondaryUserId,
                                ACTIVE_STATUSES)
                        .stream()
                        .anyMatch(active ->
                                !active.getId().equals(
                                        intentId));
        if (secondaryAlreadyParticipates) {
            throw failure(
                    AccountMergeFailureCode
                            .MERGE_CONFLICT);
        }
        Instant now = now();
        intent.recordSecondaryProof(
                secondaryUserId,
                method,
                now);
        recordAudit(
                actor,
                "ACCOUNT_MERGE_SECONDARY_REAUTHENTICATED",
                intent,
                method);
        return toIntent(intent);
    }

    @Transactional(noRollbackFor = AccountMergeException.class)
    public AccountMergePreview preview(
            AccountMergeActor actor,
            UUID intentId) {
        AccountMergeIntentEntity intent =
                requireActiveIntent(actor, intentId);
        if (intent.getStatus()
                != AccountMergeIntentStatus.READY_FOR_PREVIEW
                && intent.getStatus()
                        != AccountMergeIntentStatus
                                .READY_TO_CONFIRM
                && intent.getStatus()
                        != AccountMergeIntentStatus
                                .FAILED_CONFLICT) {
            throw failure(
                    AccountMergeFailureCode
                            .MERGE_ALREADY_CONSUMED);
        }
        String secondaryUserId = requireSecondaryUserId(intent);
        lockEligibleAccounts(
                actor.userId(),
                secondaryUserId);
        Instant now = now();
        AccountMergePlan plan = dataGateway.inspect(
                actor.userId(),
                secondaryUserId,
                now);
        int version = intent.recordPreview(
                plan.digest(),
                plan.confirmable(),
                now);
        recordAudit(
                actor,
                "ACCOUNT_MERGE_PREVIEWED",
                intent,
                plan.confirmable()
                        ? "ready_to_confirm"
                        : "blocked_conflict");
        intentRepository.flush();
        return new AccountMergePreview(
                intent.getId(),
                intent.getStatus(),
                version,
                intent.getExpiresAt(),
                plan);
    }

    @Transactional(
            isolation = Isolation.SERIALIZABLE,
            noRollbackFor = AccountMergeException.class)
    public AccountMergeCompletion confirm(
            AccountMergeActor actor,
            UUID intentId,
            int previewVersion) {
        AccountMergeIntentEntity intent =
                requireActiveIntent(actor, intentId);
        if (intent.getStatus()
                != AccountMergeIntentStatus.READY_TO_CONFIRM
                || intent.getPreviewVersion() == null
                || intent.getPreviewVersion() != previewVersion) {
            throw failure(
                    AccountMergeFailureCode
                            .MERGE_PREVIEW_STALE);
        }
        String secondaryUserId = requireSecondaryUserId(intent);
        AccountPair accounts = lockEligibleAccounts(
                actor.userId(),
                secondaryUserId);
        Instant now = now();
        AccountMergePlan current = dataGateway.inspect(
                actor.userId(),
                secondaryUserId,
                now);
        if (!current.confirmable()
                || !current.digest().equals(
                        intent.getPreviewDigest())) {
            intent.markPreviewStale(now);
            recordAudit(
                    actor,
                    "ACCOUNT_MERGE_REJECTED",
                    intent,
                    "preview_stale");
            intentRepository.flush();
            throw failure(
                    AccountMergeFailureCode
                            .MERGE_PREVIEW_STALE);
        }
        recordAudit(
                actor,
                "ACCOUNT_MERGE_CONFIRMED",
                intent,
                "confirmed");
        dataGateway.apply(
                actor.userId(),
                secondaryUserId,
                intentId,
                current,
                now);
        accounts.secondary().setStatus(UserStatus.MERGED);
        accounts.secondary().setMergedToUserId(
                accounts.primary().getId());
        userRepository.save(accounts.secondary());
        intent.complete(now);
        recordAudit(
                actor,
                "ACCOUNT_MERGE_COMPLETED",
                intent,
                "completed");
        intentRepository.flush();
        return new AccountMergeCompletion(
                intent.getId(),
                intent.getStatus(),
                intent.getCompletedAt());
    }

    @Transactional(noRollbackFor = AccountMergeException.class)
    public AccountMergeIntent cancel(
            AccountMergeActor actor,
            UUID intentId) {
        AccountMergeIntentEntity intent =
                requireActiveIntent(actor, intentId);
        Instant now = now();
        intent.cancel(now);
        recordAudit(
                actor,
                "ACCOUNT_MERGE_CANCELLED",
                intent,
                "cancelled");
        intentRepository.flush();
        return toIntent(intent);
    }

    @Transactional
    public int expireDueIntents(int batchSize) {
        if (batchSize < 1 || batchSize > 1000) {
            throw new IllegalArgumentException(
                    "Invalid account merge expiration batch size");
        }
        Instant now = now();
        List<AccountMergeIntentEntity> expired =
                intentRepository.findExpiredForUpdate(
                        now,
                        ACTIVE_STATUSES,
                        PageRequest.of(0, batchSize));
        for (AccountMergeIntentEntity intent : expired) {
            intent.expire(now);
            auditLogService.record(
                    intent.getPrimaryUserId(),
                    "ACCOUNT_MERGE_EXPIRED",
                    "ACCOUNT_MERGE_INTENT",
                    null,
                    null,
                    null,
                    null,
                    "{\"intentId\":\""
                            + intent.getId()
                            + "\",\"result\":\"expired\"}");
        }
        if (!expired.isEmpty()) {
            intentRepository.flush();
        }
        return expired.size();
    }

    private void expireExistingIntent(
            AccountMergeActor actor,
            Instant now) {
        for (AccountMergeIntentEntity existing
                : intentRepository
                        .findActiveByParticipantForUpdate(
                                actor.userId(),
                                ACTIVE_STATUSES)) {
            if (!existing.isExpiredAt(now)) {
                throw failure(
                        AccountMergeFailureCode
                                .MERGE_CONFLICT);
            }
            existing.expire(now);
            recordAudit(
                    actor,
                    "ACCOUNT_MERGE_EXPIRED",
                    existing,
                    "expired");
            intentRepository.flush();
        }
    }

    private AccountMergeIntentEntity requireActiveIntent(
            AccountMergeActor actor,
            UUID intentId) {
        AccountMergeIntentEntity intent =
                intentRepository.findByIdForUpdate(intentId)
                        .orElseThrow(() ->
                                failure(
                                        AccountMergeFailureCode
                                                .MERGE_INTENT_NOT_FOUND));
        if (!intent.getPrimaryUserId().equals(
                actor.userId())) {
            throw failure(
                    AccountMergeFailureCode
                            .MERGE_SESSION_MISMATCH);
        }
        if (!stateHasher.matches(
                actor.sessionNonce(),
                intent.getPrimarySessionNonceHash())) {
            throw failure(
                    AccountMergeFailureCode
                            .MERGE_SESSION_MISMATCH);
        }
        if (!intent.getStatus().isActive()) {
            throw failure(
                    AccountMergeFailureCode
                            .MERGE_ALREADY_CONSUMED);
        }
        Instant now = now();
        if (intent.isExpiredAt(now)) {
            intent.expire(now);
            recordAudit(
                    actor,
                    "ACCOUNT_MERGE_EXPIRED",
                    intent,
                    "expired");
            intentRepository.flush();
            throw failure(
                    AccountMergeFailureCode
                            .MERGE_PROOF_EXPIRED);
        }
        return intent;
    }

    private AccountPair lockEligibleAccounts(
            String firstUserId,
            String secondUserId) {
        List<String> ordered = List.of(
                        firstUserId,
                        secondUserId)
                .stream()
                .sorted(Comparator.naturalOrder())
                .toList();
        UserAccount first = requireEligibleAccount(
                ordered.get(0));
        UserAccount second = requireEligibleAccount(
                ordered.get(1));
        UserAccount primary = first.getId().equals(firstUserId)
                ? first
                : second;
        UserAccount secondary = first.getId().equals(
                secondUserId)
                ? first
                : second;
        return new AccountPair(primary, secondary);
    }

    private UserAccount requireEligiblePrimary(String userId) {
        return requireEligibleAccount(userId);
    }

    private UserAccount requireEligibleAccount(String userId) {
        UserAccount user = userRepository
                .findByIdForUpdate(userId)
                .orElseThrow(() ->
                        failure(
                                AccountMergeFailureCode
                                        .MERGE_ACCOUNT_NOT_ELIGIBLE));
        if (accountLoginGuard.evaluateInteractive(user)
                != AccountLoginDecision.ALLOWED
                || user.isSystemAccount()
                || user.getMergedToUserId() != null) {
            throw failure(
                    AccountMergeFailureCode
                            .MERGE_ACCOUNT_NOT_ELIGIBLE);
        }
        return user;
    }

    private String requireSecondaryUserId(
            AccountMergeIntentEntity intent) {
        if (intent.getSecondaryUserId() == null) {
            throw failure(
                    AccountMergeFailureCode
                            .MERGE_REAUTH_REQUIRED);
        }
        return intent.getSecondaryUserId();
    }

    private void recordAudit(
            AccountMergeActor actor,
            String action,
            AccountMergeIntentEntity intent,
            String result) {
        IdentityLoginContext context = actor.auditContext();
        auditLogService.record(
                actor.userId(),
                action,
                "ACCOUNT_MERGE_INTENT",
                null,
                context.requestId(),
                context.clientIp(),
                context.userAgent(),
                "{\"intentId\":\""
                        + intent.getId()
                        + "\",\"result\":\""
                        + result
                        + "\"}");
    }

    private AccountMergeIntent toIntent(
            AccountMergeIntentEntity intent) {
        return new AccountMergeIntent(
                intent.getId(),
                intent.getStatus(),
                intent.getExpiresAt());
    }

    private Instant now() {
        return Instant.now(clock);
    }

    private Instant earliest(Instant first, Instant second) {
        return first.isBefore(second) ? first : second;
    }

    private AccountMergeException failure(
            AccountMergeFailureCode code) {
        return new AccountMergeException(code);
    }

    private record AccountPair(
            UserAccount primary,
            UserAccount secondary) {
    }
}
