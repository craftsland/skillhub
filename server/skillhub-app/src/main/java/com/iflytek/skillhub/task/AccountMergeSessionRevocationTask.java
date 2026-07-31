package com.iflytek.skillhub.task;

import com.iflytek.skillhub.auth.merge.AccountMergeMetrics;
import com.iflytek.skillhub.domain.audit.AuditLogService;
import com.iflytek.skillhub.notification.sse.SseEmitterManager;
import com.iflytek.skillhub.repository.AccountMergeSessionRevocationRepository;
import com.iflytek.skillhub.repository.AccountMergeSessionRevocationRepository.Claim;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.stereotype.Component;

/**
 * Reliably deletes every Spring Session indexed to a merged secondary user.
 */
@Component
@ConditionalOnBean(FindByIndexNameSessionRepository.class)
public class AccountMergeSessionRevocationTask {

    static final Duration LEASE_DURATION = Duration.ofMinutes(2);
    static final int MAX_BATCH_SIZE = 10;
    static final String SESSION_STORE_FAILURE =
            "SESSION_STORE_FAILURE";
    static final String SESSION_DELETE_INCOMPLETE =
            "SESSION_DELETE_INCOMPLETE";

    private static final Logger log = LoggerFactory.getLogger(
            AccountMergeSessionRevocationTask.class);

    private final AccountMergeSessionRevocationRepository repository;
    private final FindByIndexNameSessionRepository<? extends Session>
            sessionRepository;
    private final SseEmitterManager sseEmitterManager;
    private final AccountMergeMetrics metrics;
    private final AuditLogService auditLogService;
    private final Clock clock;

    public AccountMergeSessionRevocationTask(
            AccountMergeSessionRevocationRepository repository,
            FindByIndexNameSessionRepository<? extends Session>
                    sessionRepository,
            SseEmitterManager sseEmitterManager,
            AccountMergeMetrics metrics,
            AuditLogService auditLogService,
            Clock clock) {
        this.repository = repository;
        this.sessionRepository = sessionRepository;
        this.sseEmitterManager = sseEmitterManager;
        this.metrics = metrics;
        this.auditLogService = auditLogService;
        this.clock = clock;
    }

    @Scheduled(
            fixedDelayString =
                    "${skillhub.auth.account-merge."
                            + "session-revocation.poll-interval-ms:5000}")
    public void processDueRevocations() {
        for (int processed = 0;
                processed < MAX_BATCH_SIZE;
                processed++) {
            Instant now = Instant.now(clock);
            var claim = repository.claimNext(
                    now,
                    LEASE_DURATION);
            if (claim.isEmpty()) {
                return;
            }
            process(claim.orElseThrow());
        }
    }

    private void process(Claim claim) {
        try {
            sseEmitterManager.closeAll(claim.userId());
            deleteIndexedSessions(claim.userId());
            if (repository.complete(
                    claim,
                    Instant.now(clock))) {
                metrics.recordSessionRevocation("success");
            }
        } catch (RuntimeException exception) {
            Instant now = Instant.now(clock);
            String errorCode =
                    exception instanceof IncompleteDeletionException
                            ? SESSION_DELETE_INCOMPLETE
                            : SESSION_STORE_FAILURE;
            boolean scheduled = repository.retry(
                    claim,
                    now.plus(backoff(claim.attemptCount())),
                    errorCode,
                    now);
            if (scheduled) {
                metrics.recordSessionRevocation("retry");
                recordRetryAudit(claim, errorCode);
                log.warn(
                        "Account merge session revocation will retry "
                                + "[taskId={}, attempt={}, reason={}]",
                        claim.id(),
                        claim.attemptCount(),
                        errorCode);
            }
        }
    }

    private void recordRetryAudit(
            Claim claim,
            String errorCode) {
        try {
            auditLogService.record(
                    claim.userId(),
                    "ACCOUNT_MERGE_SESSION_REVOCATION_RETRIED",
                    "ACCOUNT_MERGE_SESSION_REVOCATION",
                    claim.id(),
                    null,
                    null,
                    null,
                    "{\"attempt\":"
                            + claim.attemptCount()
                            + ",\"reason\":\""
                            + errorCode
                            + "\"}");
        } catch (RuntimeException exception) {
            log.error(
                    "Failed to persist account merge session "
                            + "revocation retry audit [taskId={}]",
                    claim.id(),
                    exception);
        }
    }

    private void deleteIndexedSessions(String userId) {
        Map<String, ? extends Session> sessions =
                sessionRepository.findByPrincipalName(userId);
        for (String sessionId : sessions.keySet()) {
            sessionRepository.deleteById(sessionId);
        }
        if (!sessionRepository.findByPrincipalName(userId)
                .isEmpty()) {
            throw new IncompleteDeletionException();
        }
    }

    static Duration backoff(int attemptCount) {
        int exponent = Math.max(
                0,
                Math.min(attemptCount - 1, 6));
        return Duration.ofSeconds(
                Math.min(300L, 5L << exponent));
    }

    private static final class IncompleteDeletionException
            extends RuntimeException {
        private IncompleteDeletionException() {
            super(SESSION_DELETE_INCOMPLETE);
        }
    }
}
