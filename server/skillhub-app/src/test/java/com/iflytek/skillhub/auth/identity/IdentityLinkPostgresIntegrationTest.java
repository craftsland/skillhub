package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@SpringBootTest
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@EnabledIfEnvironmentVariable(
        named = "IDENTITY_BINDING_V2_POSTGRES_URL",
        matches = "jdbc:postgresql:.*")
class IdentityLinkPostgresIntegrationTest {

    private static final String SCHEMA =
            "identity_link_pr655_integration";
    private static final String PASSWORD =
            "IdentityLinkTest!2026";
    private static final IdentityLoginContext CONTEXT =
            new IdentityLoginContext(
                    "req-pr655",
                    "203.0.113.9",
                    "Identity Link Integration Test");

    @Autowired
    private IdentityLinkIntentService intentService;

    @Autowired
    private ExternalIdentityLinkService externalLinkService;

    @Autowired
    private TrustedProviderRouteResolver routeResolver;

    @Autowired
    private ClientRegistrationRepository registrationRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @DynamicPropertySource
    static void postgresProperties(
            DynamicPropertyRegistry registry) {
        String url = requiredEnvironment(
                "IDENTITY_BINDING_V2_POSTGRES_URL");
        String username = requiredEnvironment(
                "IDENTITY_BINDING_V2_POSTGRES_USERNAME");
        String password = requiredEnvironment(
                "IDENTITY_BINDING_V2_POSTGRES_PASSWORD");
        createSchema(url, username, password);
        registry.add(
                "spring.datasource.url",
                () -> withCurrentSchema(url));
        registry.add(
                "spring.datasource.username",
                () -> username);
        registry.add(
                "spring.datasource.password",
                () -> password);
        registry.add(
                "spring.datasource.driver-class-name",
                () -> "org.postgresql.Driver");
        registry.add(
                "spring.jpa.database-platform",
                () -> "org.hibernate.dialect.PostgreSQLDialect");
        registry.add(
                "spring.jpa.hibernate.ddl-auto",
                () -> "validate");
        registry.add(
                "spring.flyway.enabled",
                () -> "true");
        registry.add(
                "spring.flyway.default-schema",
                () -> SCHEMA);
        registry.add(
                "spring.flyway.schemas",
                () -> SCHEMA);
        registry.add(
                "skillhub.builtin-skills.enabled",
                () -> "false");
    }

    @AfterAll
    static void dropSchema() {
        String url = requiredEnvironment(
                "IDENTITY_BINDING_V2_POSTGRES_URL");
        String username = requiredEnvironment(
                "IDENTITY_BINDING_V2_POSTGRES_USERNAME");
        String password = requiredEnvironment(
                "IDENTITY_BINDING_V2_POSTGRES_PASSWORD");
        try (Connection connection =
                DriverManager.getConnection(
                        url,
                        username,
                        password);
                Statement statement =
                        connection.createStatement()) {
            statement.execute(
                    "DROP SCHEMA IF EXISTS "
                            + SCHEMA
                            + " CASCADE");
        } catch (Exception exception) {
            throw new IllegalStateException(
                    "Failed to remove identity link test schema",
                    exception);
        }
    }

    @Test
    void linkRequiresFreshReauthenticationAndCannotBeReplayed() {
        String userId = "identity-link-user";
        String subject = "6551001";
        seedLocalUser(userId, "identity_link_user");
        IdentityLinkActor actor = actor(
                userId,
                "nonce-link-user");
        UUID intentId = UUID.randomUUID();
        intentService.createLinkIntent(
                actor,
                intentId,
                "github");
        intentService.reauthenticateLocal(
                actor,
                intentId,
                PASSWORD);

        IdentityLinkOutcome outcome = externalLinkService.link(
                actor,
                intentId,
                githubProvider(),
                githubResult(subject));

        assertThat(outcome)
                .isInstanceOf(IdentityLinkOutcome.Linked.class);
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM identity_binding
                WHERE user_id = ?
                  AND provider_code = 'github'
                  AND subject = ?
                  AND status = 'ACTIVE'
                """,
                userId,
                subject)).isEqualTo(1L);
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM identity_binding_subject
                WHERE provider_code = 'github'
                  AND subject_value = ?
                  AND status = 'ACTIVE'
                  AND is_primary = TRUE
                """,
                subject)).isEqualTo(1L);
        assertThatThrownBy(() ->
                externalLinkService.link(
                        actor,
                        intentId,
                        githubProvider(),
                        githubResult(subject)))
                .isInstanceOfSatisfying(
                        IdentityLinkException.class,
                        exception -> assertThat(
                                exception.getReasonCode())
                                .isEqualTo(
                                        IdentityLinkFailureCode
                                                .ALREADY_CONSUMED));
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM audit_log
                WHERE action = 'IDENTITY_LINK_INTENT_REJECTED'
                  AND detail_json ->> 'intentId' = ?
                  AND detail_json ->> 'result' = 'already_consumed'
                """,
                intentId.toString())).isEqualTo(1L);
    }

    @Test
    void concurrentConsumptionOfSameIntentCompletesExactlyOnce()
            throws Exception {
        String userId = "identity-link-intent-race";
        String subject = "6551501";
        seedLocalUser(
                userId,
                "identity_link_intent_race");
        IdentityLinkActor actor =
                actor(userId, "nonce-intent-race");
        UUID intentId = readyLinkIntent(
                actor,
                PASSWORD);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Object>> futures = new ArrayList<>();

        try (var executor =
                Executors.newVirtualThreadPerTaskExecutor()) {
            for (int attempt = 0; attempt < 2; attempt++) {
                futures.add(executor.submit(() -> {
                    start.await();
                    return linkOrFailure(
                            actor,
                            intentId,
                            subject);
                }));
            }
            start.countDown();
            List<Object> results = List.of(
                    futures.get(0).get(),
                    futures.get(1).get());

            assertThat(results.stream()
                    .filter(IdentityLinkOutcome.Linked.class::isInstance)
                    .count()).isEqualTo(1L);
            assertThat(results.stream()
                    .filter(IdentityLinkException.class::isInstance)
                    .map(IdentityLinkException.class::cast)
                    .map(IdentityLinkException::getReasonCode))
                    .containsExactly(
                            IdentityLinkFailureCode.ALREADY_CONSUMED);
        }

        assertThat(count(
                """
                SELECT COUNT(*)
                FROM identity_binding
                WHERE user_id = ?
                  AND provider_code = 'github'
                  AND subject = ?
                  AND status = 'ACTIVE'
                """,
                userId,
                subject)).isEqualTo(1L);
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM identity_link_request
                WHERE id = ?
                  AND status = 'COMPLETED'
                """,
                intentId)).isEqualTo(1L);
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM audit_log
                WHERE action = 'IDENTITY_LINK_INTENT_REJECTED'
                  AND detail_json ->> 'intentId' = ?
                  AND detail_json ->> 'result' = 'already_consumed'
                """,
                intentId.toString())).isEqualTo(1L);
    }

    @Test
    void concurrentSubjectConflictLeavesOneBindingAndReadyLosingIntent()
            throws Exception {
        String firstUser = "identity-link-race-a";
        String secondUser = "identity-link-race-b";
        String subject = "6552001";
        seedLocalUser(firstUser, "identity_link_race_a");
        seedLocalUser(secondUser, "identity_link_race_b");
        IdentityLinkActor firstActor =
                actor(firstUser, "nonce-race-a");
        IdentityLinkActor secondActor =
                actor(secondUser, "nonce-race-b");
        UUID firstIntent = readyLinkIntent(
                firstActor,
                PASSWORD);
        UUID secondIntent = readyLinkIntent(
                secondActor,
                PASSWORD);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Object>> futures = new ArrayList<>();

        try (var executor =
                Executors.newVirtualThreadPerTaskExecutor()) {
            futures.add(executor.submit(() -> {
                start.await();
                return linkOrFailure(
                        firstActor,
                        firstIntent,
                        subject);
            }));
            futures.add(executor.submit(() -> {
                start.await();
                return linkOrFailure(
                        secondActor,
                        secondIntent,
                        subject);
            }));
            start.countDown();
            List<Object> results = List.of(
                    futures.get(0).get(),
                    futures.get(1).get());

            assertThat(results.stream()
                    .filter(IdentityLinkOutcome.Linked.class::isInstance)
                    .count()).isEqualTo(1L);
            assertThat(results.stream()
                    .filter(IdentityLinkException.class::isInstance)
                    .map(IdentityLinkException.class::cast)
                    .map(IdentityLinkException::getReasonCode))
                    .containsExactly(
                            IdentityLinkFailureCode.IDENTITY_IN_USE);
        }

        assertThat(count(
                """
                SELECT COUNT(*)
                FROM identity_binding
                WHERE provider_code = 'github'
                  AND subject = ?
                  AND status = 'ACTIVE'
                """,
                subject)).isEqualTo(1L);
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM identity_link_request
                WHERE id IN (?, ?)
                  AND status = 'READY'
                """,
                firstIntent,
                secondIntent)).isEqualTo(1L);
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM identity_link_request
                WHERE id IN (?, ?)
                  AND status = 'COMPLETED'
                """,
                firstIntent,
                secondIntent)).isEqualTo(1L);
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM audit_log
                WHERE action = 'IDENTITY_LINK_INTENT_REJECTED'
                  AND detail_json ->> 'intentId' IN (?, ?)
                  AND detail_json ->> 'result' = 'identity_in_use'
                """,
                firstIntent.toString(),
                secondIntent.toString())).isEqualTo(1L);
    }

    @Test
    void unlinkRejectsFinalMethodThenRevokesBindingAndSubjectsAtomically() {
        String userId = "identity-unlink-user";
        String subject = "6553001";
        String username = "identity_unlink_user";
        seedLocalUser(userId, username);
        IdentityLinkActor actor = actor(
                userId,
                "nonce-unlink-user");
        UUID linkIntent = readyLinkIntent(actor, PASSWORD);
        IdentityLinkOutcome.Linked linked =
                (IdentityLinkOutcome.Linked)
                        externalLinkService.link(
                                actor,
                                linkIntent,
                                githubProvider(),
                                githubResult(subject));
        jdbcTemplate.update(
                "DELETE FROM local_credential WHERE user_id = ?",
                userId);
        UUID unlinkIntent = UUID.randomUUID();
        intentService.createUnlinkIntent(
                actor,
                unlinkIntent,
                linked.bindingId());
        externalLinkService.reauthenticate(
                actor,
                unlinkIntent,
                githubProvider(),
                githubResult(subject));

        assertThatThrownBy(() ->
                intentService.completeUnlink(
                        actor,
                        unlinkIntent))
                .isInstanceOfSatisfying(
                        IdentityLinkException.class,
                        exception -> assertThat(
                                exception.getReasonCode())
                                .isEqualTo(
                                        IdentityLinkFailureCode
                                                .FINAL_LOGIN_METHOD));
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM identity_binding
                WHERE id = ?
                  AND status = 'ACTIVE'
                """,
                linked.bindingId())).isEqualTo(1L);

        insertLocalCredential(userId, username);
        intentService.completeUnlink(actor, unlinkIntent);

        assertThat(count(
                """
                SELECT COUNT(*)
                FROM identity_binding
                WHERE id = ?
                  AND status = 'REVOKED'
                  AND revoked_by = ?
                """,
                linked.bindingId(),
                userId)).isEqualTo(1L);
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM identity_binding_subject
                WHERE binding_id = ?
                  AND status = 'REVOKED'
                  AND is_primary = FALSE
                """,
                linked.bindingId())).isEqualTo(1L);
    }

    @Test
    void unavailableLegacyProviderCanStillBeSafelyUnlinked() {
        String userId = "identity-unlink-legacy-provider";
        String username = "identity_unlink_legacy_provider";
        String providerCode = "legacy-missing";
        String subject = "legacy-missing-655";
        seedLocalUser(userId, username);
        long bindingId = insertLegacyBinding(
                userId,
                providerCode,
                subject,
                username);

        IdentityLinkBindingView legacyBinding =
                intentService.accountState(userId)
                        .linkedProviders()
                        .stream()
                        .filter(binding ->
                                binding.bindingId()
                                        == bindingId)
                        .findFirst()
                        .orElseThrow();
        assertThat(legacyBinding.usable()).isFalse();
        assertThat(legacyBinding.canUnlink()).isTrue();

        IdentityLinkActor actor = actor(
                userId,
                "nonce-unlink-legacy-provider");
        UUID intentId = UUID.randomUUID();
        intentService.createUnlinkIntent(
                actor,
                intentId,
                bindingId);
        intentService.reauthenticateLocal(
                actor,
                intentId,
                PASSWORD);
        intentService.completeUnlink(actor, intentId);

        assertThat(count(
                """
                SELECT COUNT(*)
                FROM identity_binding
                WHERE id = ?
                  AND status = 'REVOKED'
                """,
                bindingId)).isEqualTo(1L);
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM identity_provider_state
                WHERE provider_code = ?
                """,
                providerCode)).isZero();
    }

    @Test
    void unlinkedIdentityCanBeLinkedAgainWhileRevocationHistoryIsPreserved() {
        String userId = "identity-relink-user";
        String subject = "6554001";
        seedLocalUser(userId, "identity_relink_user");
        IdentityLinkActor actor = actor(
                userId,
                "nonce-relink-user");
        UUID firstLinkIntent = readyLinkIntent(actor, PASSWORD);
        IdentityLinkOutcome.Linked firstLink =
                (IdentityLinkOutcome.Linked)
                        externalLinkService.link(
                                actor,
                                firstLinkIntent,
                                githubProvider(),
                                githubResult(subject));
        UUID unlinkIntent = UUID.randomUUID();
        intentService.createUnlinkIntent(
                actor,
                unlinkIntent,
                firstLink.bindingId());
        intentService.reauthenticateLocal(
                actor,
                unlinkIntent,
                PASSWORD);
        intentService.completeUnlink(actor, unlinkIntent);

        UUID secondLinkIntent = readyLinkIntent(actor, PASSWORD);
        IdentityLinkOutcome.Linked secondLink =
                (IdentityLinkOutcome.Linked)
                        externalLinkService.link(
                                actor,
                                secondLinkIntent,
                                githubProvider(),
                                githubResult(subject));

        assertThat(secondLink.bindingId())
                .isNotEqualTo(firstLink.bindingId());
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM identity_binding
                WHERE provider_code = 'github'
                  AND subject = ?
                  AND status = 'ACTIVE'
                """,
                subject)).isEqualTo(1L);
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM identity_binding
                WHERE provider_code = 'github'
                  AND subject = ?
                  AND status = 'REVOKED'
                """,
                subject)).isEqualTo(1L);
    }

    @Test
    void intentExpiryCommitsAndSessionNonceMismatchFailsClosed() {
        String userId = "identity-link-expiry-user";
        seedLocalUser(
                userId,
                "identity_link_expiry_user");
        String rawNonce = "raw-session-nonce-expiry";
        IdentityLinkActor actor = actor(userId, rawNonce);
        UUID expiredIntent = UUID.randomUUID();
        intentService.createLinkIntent(
                actor,
                expiredIntent,
                "github");
        String stateHash = jdbcTemplate.queryForObject(
                """
                SELECT state_hash
                FROM identity_link_request
                WHERE id = ?
                """,
                String.class,
                expiredIntent);
        assertThat(stateHash)
                .hasSize(64)
                .isNotEqualTo(rawNonce);
        jdbcTemplate.update(
                """
                UPDATE identity_link_request
                SET expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second'
                WHERE id = ?
                """,
                expiredIntent);
        UUID replacementIntent = UUID.randomUUID();

        intentService.createLinkIntent(
                actor,
                replacementIntent,
                "github");

        assertThatThrownBy(() ->
                intentService.getIntent(
                        actor,
                        expiredIntent))
                .isInstanceOfSatisfying(
                        IdentityLinkException.class,
                        exception -> assertThat(
                                exception.getReasonCode())
                                .isEqualTo(
                                        IdentityLinkFailureCode
                                                .INTENT_EXPIRED));
        assertThat(jdbcTemplate.queryForObject(
                """
                SELECT status
                FROM identity_link_request
                WHERE id = ?
                """,
                String.class,
                expiredIntent)).isEqualTo("EXPIRED");

        assertThatThrownBy(() ->
                intentService.getIntent(
                        actor(
                                userId,
                                "another-session-nonce"),
                        replacementIntent))
                .isInstanceOfSatisfying(
                        IdentityLinkException.class,
                        exception -> assertThat(
                                exception.getReasonCode())
                                .isEqualTo(
                                        IdentityLinkFailureCode
                                                .SESSION_MISMATCH));
        assertThatThrownBy(() ->
                intentService.createLinkIntent(
                        actor,
                        UUID.randomUUID(),
                        "github"))
                .isInstanceOfSatisfying(
                        IdentityLinkException.class,
                        exception -> assertThat(
                                exception.getReasonCode())
                                .isEqualTo(
                                        IdentityLinkFailureCode
                                                .ACTIVE_INTENT_EXISTS));
    }

    private UUID readyLinkIntent(
            IdentityLinkActor actor,
            String password) {
        UUID intentId = UUID.randomUUID();
        intentService.createLinkIntent(
                actor,
                intentId,
                "github");
        intentService.reauthenticateLocal(
                actor,
                intentId,
                password);
        return intentId;
    }

    private Object linkOrFailure(
            IdentityLinkActor actor,
            UUID intentId,
            String subject) {
        try {
            return externalLinkService.link(
                    actor,
                    intentId,
                    githubProvider(),
                    githubResult(subject));
        } catch (IdentityLinkException exception) {
            return exception;
        }
    }

    private IdentityLinkActor actor(
            String userId,
            String nonce) {
        return new IdentityLinkActor(
                userId,
                "local",
                nonce,
                CONTEXT);
    }

    private void seedLocalUser(
            String userId,
            String username) {
        jdbcTemplate.update(
                """
                INSERT INTO user_account (
                    id,
                    display_name,
                    email,
                    status,
                    system_account,
                    created_at,
                    updated_at
                ) VALUES (?, ?, ?, 'ACTIVE', FALSE,
                    CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                userId,
                username,
                username + "@example.com");
        insertLocalCredential(userId, username);
    }

    private void insertLocalCredential(
            String userId,
            String username) {
        jdbcTemplate.update(
                """
                INSERT INTO local_credential (
                    user_id,
                    username,
                    password_hash,
                    failed_attempts,
                    created_at,
                    updated_at
                ) VALUES (?, ?, ?, 0,
                    CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                userId,
                username,
                passwordEncoder.encode(PASSWORD));
    }

    private long insertLegacyBinding(
            String userId,
            String providerCode,
            String subject,
            String loginName) {
        Long bindingId = new TransactionTemplate(
                transactionManager).execute(status -> {
            jdbcTemplate.update(
                    """
                    INSERT INTO identity_binding (
                        user_id,
                        provider_code,
                        subject,
                        login_name,
                        status,
                        created_at,
                        updated_at
                    ) VALUES (?, ?, ?, ?, 'ACTIVE',
                        CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    """,
                    userId,
                    providerCode,
                    subject,
                    loginName);
            Long createdBindingId =
                    jdbcTemplate.queryForObject(
                            """
                            SELECT id
                            FROM identity_binding
                            WHERE user_id = ?
                              AND provider_code = ?
                              AND subject = ?
                              AND status = 'ACTIVE'
                            """,
                            Long.class,
                            userId,
                            providerCode,
                            subject);
            assertThat(createdBindingId).isNotNull();
            jdbcTemplate.update(
                    """
                    INSERT INTO identity_binding_subject (
                        binding_id,
                        provider_code,
                        subject_type,
                        subject_value,
                        is_primary,
                        status,
                        created_at,
                        last_seen_at
                    ) VALUES (?, ?, 'legacy_subject', ?, TRUE,
                        'ACTIVE', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    """,
                    createdBindingId,
                    providerCode,
                    subject);
            return createdBindingId;
        });
        if (bindingId == null) {
            throw new IllegalStateException(
                    "Legacy binding transaction returned no id");
        }
        return bindingId;
    }

    private ResolvedProviderHandle githubProvider() {
        ClientRegistration registration =
                registrationRepository.findByRegistrationId(
                        "github");
        assertThat(registration).isNotNull();
        return routeResolver.resolve(registration);
    }

    private ProviderAuthenticationResult githubResult(
            String subject) {
        return new ProviderAuthenticationResult(
                new SubjectCandidate(
                        "github_user_id",
                        subject),
                List.of(),
                Map.of(
                        "login",
                        List.of(new ProviderAttributeValue(
                                "identity-link-test",
                                ProviderAttributeTrust.ASSERTED)),
                        "email",
                        List.of(new ProviderAttributeValue(
                                subject + "@example.com",
                                ProviderAttributeTrust.VERIFIED))),
                new ProtocolAuthenticationEvidence(
                        "oauth2-github",
                        Instant.now(),
                        Set.of(
                                "oauth2_authorization_code")));
    }

    private long count(String sql, Object... arguments) {
        Long count = jdbcTemplate.queryForObject(
                sql,
                Long.class,
                arguments);
        return count == null ? 0L : count;
    }

    private static void createSchema(
            String url,
            String username,
            String password) {
        try (Connection connection =
                DriverManager.getConnection(
                        url,
                        username,
                        password);
                Statement statement =
                        connection.createStatement()) {
            statement.execute(
                    "DROP SCHEMA IF EXISTS "
                            + SCHEMA
                            + " CASCADE");
            statement.execute(
                    "CREATE SCHEMA " + SCHEMA);
        } catch (Exception exception) {
            throw new IllegalStateException(
                    "Failed to prepare identity link test schema",
                    exception);
        }
    }

    private static String withCurrentSchema(String url) {
        String separator = url.contains("?") ? "&" : "?";
        return url
                + separator
                + "currentSchema="
                + SCHEMA;
    }

    private static String requiredEnvironment(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(
                    "Missing required environment variable " + name);
        }
        return value;
    }
}
