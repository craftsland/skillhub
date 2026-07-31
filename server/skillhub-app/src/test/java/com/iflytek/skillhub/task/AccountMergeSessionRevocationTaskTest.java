package com.iflytek.skillhub.task;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.merge.AccountMergeMetrics;
import com.iflytek.skillhub.domain.audit.AuditLogService;
import com.iflytek.skillhub.notification.sse.SseEmitterManager;
import com.iflytek.skillhub.repository.AccountMergeSessionRevocationRepository;
import com.iflytek.skillhub.repository.AccountMergeSessionRevocationRepository.Claim;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;

class AccountMergeSessionRevocationTaskTest {

    private static final Instant NOW =
            Instant.parse("2026-07-31T10:00:00Z");
    private static final Clock CLOCK = Clock.fixed(
            NOW,
            ZoneOffset.UTC);

    @Test
    void closesSseDeletesEveryIndexedSessionAndCompletesTask() {
        Fixture fixture = new Fixture();
        Claim claim = claim(1);
        Session first = mock(Session.class);
        Session second = mock(Session.class);
        when(fixture.repository.claimNext(
                NOW,
                AccountMergeSessionRevocationTask
                        .LEASE_DURATION))
                .thenReturn(Optional.of(claim))
                .thenReturn(Optional.empty());
        when(fixture.sessions.findByPrincipalName("usr_secondary"))
                .thenReturn(Map.of(
                        "session-1",
                        first,
                        "session-2",
                        second))
                .thenReturn(Map.of());
        when(fixture.repository.complete(claim, NOW))
                .thenReturn(true);

        fixture.task.processDueRevocations();

        InOrder order = inOrder(
                fixture.sse,
                fixture.sessions,
                fixture.repository);
        order.verify(fixture.sse).closeAll("usr_secondary");
        order.verify(fixture.sessions)
                .findByPrincipalName("usr_secondary");
        verify(fixture.sessions).deleteById("session-1");
        verify(fixture.sessions).deleteById("session-2");
        order.verify(fixture.sessions)
                .findByPrincipalName("usr_secondary");
        order.verify(fixture.repository).complete(claim, NOW);
        verify(fixture.metrics)
                .recordSessionRevocation("success");
    }

    @Test
    void retriesWithBoundedBackoffWhenRedisDeletionFails() {
        Fixture fixture = new Fixture();
        Claim claim = claim(3);
        when(fixture.repository.claimNext(
                NOW,
                AccountMergeSessionRevocationTask
                        .LEASE_DURATION))
                .thenReturn(Optional.of(claim))
                .thenReturn(Optional.empty());
        when(fixture.sessions.findByPrincipalName("usr_secondary"))
                .thenThrow(new IllegalStateException(
                        "redis unavailable"));
        when(fixture.repository.retry(
                claim,
                NOW.plusSeconds(20),
                AccountMergeSessionRevocationTask
                        .SESSION_STORE_FAILURE,
                NOW)).thenReturn(true);

        fixture.task.processDueRevocations();

        verify(fixture.repository).retry(
                claim,
                NOW.plusSeconds(20),
                AccountMergeSessionRevocationTask
                        .SESSION_STORE_FAILURE,
                NOW);
        verify(fixture.metrics)
                .recordSessionRevocation("retry");
        verify(fixture.auditLogService).record(
                "usr_secondary",
                "ACCOUNT_MERGE_SESSION_REVOCATION_RETRIED",
                "ACCOUNT_MERGE_SESSION_REVOCATION",
                42L,
                null,
                null,
                null,
                "{\"attempt\":3,\"reason\":"
                        + "\"SESSION_STORE_FAILURE\"}");
    }

    @Test
    void retriesWhenAnIndexedSessionRemainsAfterDeletion() {
        Fixture fixture = new Fixture();
        Claim claim = claim(2);
        Session session = mock(Session.class);
        when(fixture.repository.claimNext(
                NOW,
                AccountMergeSessionRevocationTask
                        .LEASE_DURATION))
                .thenReturn(Optional.of(claim))
                .thenReturn(Optional.empty());
        when(fixture.sessions.findByPrincipalName("usr_secondary"))
                .thenReturn(Map.of("session-1", session))
                .thenReturn(Map.of("session-1", session));
        when(fixture.repository.retry(
                claim,
                NOW.plusSeconds(10),
                AccountMergeSessionRevocationTask
                        .SESSION_DELETE_INCOMPLETE,
                NOW)).thenReturn(true);

        fixture.task.processDueRevocations();

        verify(fixture.sessions).deleteById("session-1");
        verify(fixture.repository).retry(
                claim,
                NOW.plusSeconds(10),
                AccountMergeSessionRevocationTask
                        .SESSION_DELETE_INCOMPLETE,
                NOW);
        verify(fixture.metrics)
                .recordSessionRevocation("retry");
    }

    @Test
    void backoffIsExponentialAndCapped() {
        assertThat(AccountMergeSessionRevocationTask
                .backoff(1)).isEqualTo(Duration.ofSeconds(5));
        assertThat(AccountMergeSessionRevocationTask
                .backoff(4)).isEqualTo(Duration.ofSeconds(40));
        assertThat(AccountMergeSessionRevocationTask
                .backoff(100)).isEqualTo(
                        Duration.ofSeconds(300));
    }

    private static Claim claim(int attemptCount) {
        return new Claim(
                42L,
                "usr_secondary",
                attemptCount,
                NOW.plus(
                        AccountMergeSessionRevocationTask
                                .LEASE_DURATION));
    }

    private static final class Fixture {

        private final AccountMergeSessionRevocationRepository
                repository = mock(
                        AccountMergeSessionRevocationRepository.class);
        @SuppressWarnings("unchecked")
        private final FindByIndexNameSessionRepository<Session>
                sessions = mock(
                        FindByIndexNameSessionRepository.class);
        private final SseEmitterManager sse =
                mock(SseEmitterManager.class);
        private final AccountMergeMetrics metrics =
                mock(AccountMergeMetrics.class);
        private final AuditLogService auditLogService =
                mock(AuditLogService.class);
        private final AccountMergeSessionRevocationTask task =
                new AccountMergeSessionRevocationTask(
                        repository,
                        sessions,
                        sse,
                        metrics,
                        auditLogService,
                        CLOCK);
    }
}
