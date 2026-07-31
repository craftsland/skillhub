package com.iflytek.skillhub.task;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.merge.AccountMergeMetrics;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.domain.audit.AuditLogService;
import com.iflytek.skillhub.notification.sse.SseEmitterManager;
import com.iflytek.skillhub.repository.AccountMergeSessionRevocationRepository;
import com.iflytek.skillhub.repository.AccountMergeSessionRevocationRepository.Claim;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.data.redis.connection.RedisPassword;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.session.data.redis.RedisIndexedSessionRepository;
import org.springframework.session.data.redis.RedisSessionRepository;

@Tag("redis")
@EnabledIfEnvironmentVariable(named = "REDIS_TEST_HOST", matches = ".+")
class AccountMergeSessionRedisIntegrationTest {

    private static final Instant NOW =
            Instant.parse("2026-07-31T10:00:00Z");
    private static final Clock CLOCK =
            Clock.fixed(NOW, ZoneOffset.UTC);

    @Test
    void principalIndexFindsEverySessionAndRevocationDeletesOnlySecondary() {
        try (Fixture fixture = new Fixture()) {
            String secondaryFirst = fixture.createSession("usr_secondary");
            String secondarySecond = fixture.createSession("usr_secondary");
            String primary = fixture.createSession("usr_primary");

            assertThat(fixture.sessions.findByPrincipalName("usr_secondary"))
                    .containsOnlyKeys(secondaryFirst, secondarySecond);
            assertThat(fixture.sessions.findByPrincipalName("usr_primary"))
                    .containsOnlyKeys(primary);

            AccountMergeSessionRevocationRepository tasks =
                    mock(AccountMergeSessionRevocationRepository.class);
            SseEmitterManager sse = mock(SseEmitterManager.class);
            AccountMergeMetrics metrics = mock(AccountMergeMetrics.class);
            AuditLogService auditLogService =
                    mock(AuditLogService.class);
            Claim claim = claim(1);
            when(tasks.claimNext(
                    NOW,
                    AccountMergeSessionRevocationTask.LEASE_DURATION))
                    .thenReturn(Optional.of(claim))
                    .thenReturn(Optional.empty());
            when(tasks.complete(claim, NOW)).thenReturn(true);

            new AccountMergeSessionRevocationTask(
                    tasks,
                    fixture.sessions,
                    sse,
                    metrics,
                    auditLogService,
                    CLOCK).processDueRevocations();

            assertThat(fixture.sessions.findByPrincipalName("usr_secondary"))
                    .isEmpty();
            assertThat(fixture.sessions.findByPrincipalName("usr_primary"))
                    .containsOnlyKeys(primary);
            verify(sse).closeAll("usr_secondary");
            verify(tasks).complete(claim, NOW);
            verify(metrics).recordSessionRevocation("success");
        }
    }

    @Test
    void deletionFailureRetriesAndLaterClearsPrincipalIndex() {
        try (Fixture fixture = new Fixture()) {
            String secondary = fixture.createSession("usr_secondary");
            FindByIndexNameSessionRepository<Session> flakySessions =
                    spy(fixture.sessions);
            doThrow(new IllegalStateException("redis delete failed"))
                    .doCallRealMethod()
                    .when(flakySessions)
                    .deleteById(secondary);

            AccountMergeSessionRevocationRepository tasks =
                    mock(AccountMergeSessionRevocationRepository.class);
            SseEmitterManager sse = mock(SseEmitterManager.class);
            AccountMergeMetrics metrics = mock(AccountMergeMetrics.class);
            AuditLogService auditLogService =
                    mock(AuditLogService.class);
            Claim firstAttempt = claim(1);
            Claim secondAttempt = claim(2);
            when(tasks.claimNext(
                    NOW,
                    AccountMergeSessionRevocationTask.LEASE_DURATION))
                    .thenReturn(
                            Optional.of(firstAttempt),
                            Optional.empty(),
                            Optional.of(secondAttempt),
                            Optional.empty());
            when(tasks.retry(
                    firstAttempt,
                    NOW.plusSeconds(5),
                    AccountMergeSessionRevocationTask.SESSION_STORE_FAILURE,
                    NOW)).thenReturn(true);
            when(tasks.complete(secondAttempt, NOW)).thenReturn(true);

            AccountMergeSessionRevocationTask task =
                    new AccountMergeSessionRevocationTask(
                            tasks,
                            flakySessions,
                            sse,
                            metrics,
                            auditLogService,
                            CLOCK);

            task.processDueRevocations();

            assertThat(flakySessions.findByPrincipalName("usr_secondary"))
                    .containsOnlyKeys(secondary);
            verify(tasks).retry(
                    firstAttempt,
                    NOW.plusSeconds(5),
                    AccountMergeSessionRevocationTask.SESSION_STORE_FAILURE,
                    NOW);
            verify(metrics).recordSessionRevocation("retry");

            task.processDueRevocations();

            assertThat(flakySessions.findByPrincipalName("usr_secondary"))
                    .isEmpty();
            verify(tasks).complete(secondAttempt, NOW);
            verify(metrics).recordSessionRevocation("success");
        }
    }

    @Test
    void legacyRepositorySessionRemainsUnindexedAfterItIsTouched() {
        try (Fixture fixture = new Fixture()) {
            RedisSessionRepository legacyRepository =
                    new RedisSessionRepository(fixture.template);
            legacyRepository.setRedisKeyNamespace(fixture.namespace);
            SessionRepository<Session> legacySessions =
                    sessionRepository(legacyRepository);
            Session legacySession =
                    legacySessions.createSession();
            fixture.setPrincipal(legacySession, "usr_legacy");
            legacySessions.save(legacySession);

            assertThat(fixture.sessions.findByPrincipalName("usr_legacy"))
                    .isEmpty();

            Session touched =
                    fixture.sessions.findById(legacySession.getId());
            assertThat(touched).isNotNull();
            touched.setLastAccessedTime(NOW);
            fixture.sessions.save(touched);

            assertThat(fixture.sessions.findByPrincipalName("usr_legacy"))
                    .isEmpty();
        }
    }

    private static Claim claim(int attemptCount) {
        return new Claim(
                42L,
                "usr_secondary",
                attemptCount,
                NOW.plus(AccountMergeSessionRevocationTask.LEASE_DURATION));
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private static FindByIndexNameSessionRepository<Session>
            indexedSessionRepository(
                    FindByIndexNameSessionRepository repository) {
        return (FindByIndexNameSessionRepository<Session>) repository;
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private static SessionRepository<Session> sessionRepository(
            SessionRepository repository) {
        return (SessionRepository<Session>) repository;
    }

    private static final class Fixture implements AutoCloseable {

        private final LettuceConnectionFactory connectionFactory;
        private final RedisTemplate<String, Object> template;
        private final String namespace =
                "skillhub:test:account-merge:" + UUID.randomUUID();
        private final RedisIndexedSessionRepository redisSessions;
        private final FindByIndexNameSessionRepository<Session> sessions;

        private Fixture() {
            RedisStandaloneConfiguration configuration =
                    new RedisStandaloneConfiguration(
                            System.getenv("REDIS_TEST_HOST"),
                            Integer.parseInt(
                                    System.getenv().getOrDefault(
                                            "REDIS_TEST_PORT",
                                            "6379")));
            String password = System.getenv("REDIS_TEST_PASSWORD");
            if (password != null && !password.isBlank()) {
                configuration.setPassword(RedisPassword.of(password));
            }
            configuration.setDatabase(Integer.parseInt(
                    System.getenv().getOrDefault(
                            "REDIS_TEST_DATABASE",
                            "0")));

            connectionFactory =
                    new LettuceConnectionFactory(configuration);
            connectionFactory.afterPropertiesSet();

            template = new RedisTemplate<>();
            template.setConnectionFactory(connectionFactory);
            template.setKeySerializer(new StringRedisSerializer());
            template.setHashKeySerializer(new StringRedisSerializer());
            template.afterPropertiesSet();

            redisSessions = new RedisIndexedSessionRepository(template);
            redisSessions.setRedisKeyNamespace(namespace);
            redisSessions.afterPropertiesSet();
            sessions = indexedSessionRepository(redisSessions);
        }

        private String createSession(String userId) {
            Session session =
                    sessions.createSession();
            setPrincipal(session, userId);
            sessions.save(session);
            return session.getId();
        }

        private void setPrincipal(Session session, String userId) {
            PlatformPrincipal principal = new PlatformPrincipal(
                    userId,
                    userId,
                    userId + "@example.com",
                    null,
                    "local",
                    Set.of("USER"));
            session.setAttribute(
                    HttpSessionSecurityContextRepository
                            .SPRING_SECURITY_CONTEXT_KEY,
                    new SecurityContextImpl(
                            new UsernamePasswordAuthenticationToken(
                                    principal,
                                    null,
                                    List.of())));
        }

        @Override
        public void close() {
            Set<String> keys = template.keys(namespace + "*");
            if (keys != null && !keys.isEmpty()) {
                template.delete(keys);
            }
            redisSessions.destroy();
            connectionFactory.destroy();
        }
    }
}
