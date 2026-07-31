package com.iflytek.skillhub.auth.merge;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.iflytek.skillhub.auth.identity.IdentityLoginContext;
import com.iflytek.skillhub.auth.merge.AccountMergeDataGateway;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Future;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.session.FindByIndexNameSessionRepository;
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
class AccountMergePostgresIntegrationTest {

    private static final String SCHEMA =
            "account_merge_pr662_integration";

    @Autowired
    private AccountMergeIntentService intentService;

    @Autowired
    private AccountMergeDataGateway dataGateway;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @MockBean
    @SuppressWarnings("rawtypes")
    private FindByIndexNameSessionRepository sessionRepository;

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
        registry.add("spring.flyway.enabled", () -> "true");
        registry.add(
                "spring.flyway.default-schema",
                () -> SCHEMA);
        registry.add("spring.flyway.schemas", () -> SCHEMA);
        registry.add(
                "skillhub.builtin-skills.enabled",
                () -> "false");
        registry.add(
                "skillhub.auth.account-merge.enabled",
                () -> "true");
        registry.add(
                "skillhub.auth.account-merge."
                        + "session-cutover-complete",
                () -> "true");
        registry.add(
                "skillhub.auth.account-merge."
                        + "session-revocation.poll-interval-ms",
                () -> "3600000");
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
                    "Failed to remove account merge test schema",
                    exception);
        }
    }

    @Test
    void confirmMigratesCurrentStateRevokesCredentialsAndPreservesHistory() {
        String primary = "merge-full-primary";
        String secondary = "merge-full-secondary";
        seedUsers(primary, secondary);
        SeededResources resources =
                seedCompleteMergeState(primary, secondary);
        PreparedMerge merge = prepareMerge(
                primary,
                secondary,
                "merge-full");

        AccountMergeCompletion completion =
                intentService.confirm(
                        merge.actor(),
                        merge.intentId(),
                        merge.previewVersion());

        assertThat(completion.status())
                .isEqualTo(AccountMergeIntentStatus.COMPLETED);
        assertThat(singleString(
                "SELECT status FROM user_account WHERE id = ?",
                secondary)).isEqualTo("MERGED");
        assertThat(singleString(
                """
                SELECT merged_to_user_id
                FROM user_account
                WHERE id = ?
                """,
                secondary)).isEqualTo(primary);

        assertThat(count(
                """
                SELECT COUNT(*)
                FROM identity_binding
                WHERE user_id = ?
                  AND provider_code = 'github'
                  AND status = 'ACTIVE'
                """,
                primary)).isEqualTo(1L);
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM identity_binding
                WHERE user_id = ?
                  AND provider_code = 'legacy-revoked'
                  AND status = 'REVOKED'
                  AND revoked_by = ?
                """,
                secondary,
                secondary)).isEqualTo(1L);
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM local_credential
                WHERE user_id = ?
                """,
                primary)).isEqualTo(1L);
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM local_credential
                WHERE user_id = ?
                """,
                secondary)).isZero();

        assertThat(singleString(
                """
                SELECT role
                FROM namespace_member
                WHERE namespace_id = ?
                  AND user_id = ?
                """,
                resources.sharedNamespaceId(),
                primary)).isEqualTo("ADMIN");
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM namespace_member
                WHERE namespace_id = ?
                  AND user_id = ?
                """,
                resources.secondaryNamespaceId(),
                primary)).isEqualTo(1L);
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM namespace_member
                WHERE user_id = ?
                """,
                secondary)).isZero();

        assertThat(count(
                "SELECT COUNT(*) FROM skill WHERE owner_id = ?",
                secondary)).isZero();
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM skill_search_document
                WHERE skill_id = ?
                  AND owner_id = ?
                """,
                resources.secondarySkillId(),
                primary)).isEqualTo(1L);

        assertThat(count(
                """
                SELECT COUNT(*)
                FROM skill_star
                WHERE skill_id = ?
                """,
                resources.sharedSkillId())).isEqualTo(1L);
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM skill_star
                WHERE skill_id = ?
                  AND user_id = ?
                """,
                resources.secondarySkillId(),
                primary)).isEqualTo(1L);
        assertThat(singleLong(
                "SELECT star_count FROM skill WHERE id = ?",
                resources.sharedSkillId())).isEqualTo(1L);
        assertThat(singleLong(
                """
                SELECT subscription_count
                FROM skill
                WHERE id = ?
                """,
                resources.sharedSkillId())).isEqualTo(1L);
        assertThat(singleLong(
                "SELECT rating_count FROM skill WHERE id = ?",
                resources.sharedSkillId())).isEqualTo(1L);
        assertThat(singleString(
                "SELECT rating_avg::text FROM skill WHERE id = ?",
                resources.sharedSkillId())).isEqualTo("5.00");

        assertThat(count(
                """
                SELECT COUNT(*)
                FROM api_token
                WHERE user_id = ?
                  AND subject_id = ?
                  AND revoked_at IS NOT NULL
                """,
                secondary,
                secondary)).isEqualTo(2L);
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM password_reset_request
                WHERE user_id = ?
                  AND consumed_at IS NOT NULL
                """,
                secondary)).isEqualTo(1L);
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM notification
                WHERE recipient_id = ?
                """,
                primary)).isEqualTo(1L);
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM notification_preference
                WHERE user_id = ?
                """,
                primary)).isEqualTo(2L);
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM notification_preference
                WHERE user_id = ?
                """,
                secondary)).isZero();
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM user_notification
                WHERE user_id = ?
                """,
                primary)).isEqualTo(1L);

        assertThat(count(
                """
                SELECT COUNT(*)
                FROM audit_log
                WHERE actor_user_id = ?
                  AND action = 'HISTORICAL_ACTION'
                """,
                secondary)).isEqualTo(1L);
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM account_merge_session_revocation
                WHERE merge_intent_id = ?
                  AND user_id = ?
                  AND status = 'PENDING'
                """,
                merge.intentId(),
                secondary)).isEqualTo(1L);
    }

    @Test
    void expiredUnrevokedTokenMakesPreviewStaleWithoutPartialMigration() {
        String primary = "merge-stale-primary";
        String secondary = "merge-stale-secondary";
        seedUsers(primary, secondary);
        PreparedMerge merge = prepareMerge(
                primary,
                secondary,
                "merge-stale");
        insertToken(
                secondary,
                "created-after-preview",
                "stale001",
                "c");
        jdbcTemplate.update("""
                UPDATE api_token
                SET expires_at =
                    CURRENT_TIMESTAMP - INTERVAL '1 minute'
                WHERE user_id = ?
                  AND name = 'created-after-preview'
                """,
                secondary);

        assertThatThrownBy(() ->
                intentService.confirm(
                        merge.actor(),
                        merge.intentId(),
                        merge.previewVersion()))
                .isInstanceOfSatisfying(
                        AccountMergeException.class,
                        exception -> assertThat(
                                exception.getReasonCode())
                                .isEqualTo(
                                        AccountMergeFailureCode
                                                .MERGE_PREVIEW_STALE));

        assertThat(singleString(
                "SELECT status FROM user_account WHERE id = ?",
                secondary)).isEqualTo("ACTIVE");
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM api_token
                WHERE user_id = ?
                  AND revoked_at IS NULL
                """,
                secondary)).isEqualTo(1L);
        assertThat(singleString(
                """
                SELECT status
                FROM account_merge_intent
                WHERE id = ?
                """,
                merge.intentId()))
                .isEqualTo("READY_FOR_PREVIEW");
    }

    @Test
    void concurrentConfirmationCommitsExactlyOnce() throws Exception {
        String primary = "merge-race-primary";
        String secondary = "merge-race-secondary";
        seedUsers(primary, secondary);
        PreparedMerge merge = prepareMerge(
                primary,
                secondary,
                "merge-race");
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Object>> futures = new ArrayList<>();

        try (var executor =
                java.util.concurrent.Executors
                        .newVirtualThreadPerTaskExecutor()) {
            for (int index = 0; index < 2; index++) {
                futures.add(executor.submit(() -> {
                    start.await();
                    try {
                        return intentService.confirm(
                                merge.actor(),
                                merge.intentId(),
                                merge.previewVersion());
                    } catch (Throwable failure) {
                        return failure;
                    }
                }));
            }
            start.countDown();
            List<Object> outcomes = new ArrayList<>();
            for (Future<Object> future : futures) {
                outcomes.add(future.get());
            }

            assertThat(outcomes.stream()
                    .filter(AccountMergeCompletion.class::isInstance)
                    .count()).isEqualTo(1L);
            assertThat(outcomes.stream()
                    .filter(AccountMergeException.class::isInstance)
                    .map(AccountMergeException.class::cast)
                    .map(AccountMergeException::getReasonCode))
                    .containsExactly(
                            AccountMergeFailureCode
                                    .MERGE_ALREADY_CONSUMED);
        }

        assertThat(count(
                """
                SELECT COUNT(*)
                FROM account_merge_session_revocation
                WHERE merge_intent_id = ?
                """,
                merge.intentId())).isEqualTo(1L);
    }

    @Test
    void failureAtTheFinalRepositoryStepRollsBackAllEarlierMoves() {
        String primary = "merge-rollback-primary";
        String secondary = "merge-rollback-secondary";
        seedUsers(primary, secondary);
        insertCredentials(primary, secondary);
        insertToken(
                secondary,
                "rollback-token",
                "rollback",
                "d");
        PreparedMerge merge = prepareMerge(
                primary,
                secondary,
                "merge-rollback");
        installSessionTaskFailureTrigger();
        try {
            assertThatThrownBy(() ->
                    intentService.confirm(
                            merge.actor(),
                            merge.intentId(),
                            merge.previewVersion()))
                    .isInstanceOf(RuntimeException.class);
        } finally {
            removeSessionTaskFailureTrigger();
        }

        assertThat(singleString(
                "SELECT status FROM user_account WHERE id = ?",
                secondary)).isEqualTo("ACTIVE");
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM local_credential
                WHERE user_id = ?
                """,
                secondary)).isEqualTo(1L);
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM api_token
                WHERE user_id = ?
                  AND revoked_at IS NULL
                """,
                secondary)).isEqualTo(1L);
        assertThat(singleString(
                """
                SELECT status
                FROM account_merge_intent
                WHERE id = ?
                """,
                merge.intentId()))
                .isEqualTo("READY_TO_CONFIRM");
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM account_merge_session_revocation
                WHERE merge_intent_id = ?
                """,
                merge.intentId())).isZero();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("atomicFailureStages")
    void failureAtEveryRequiredStageRollsBackTheWholeMerge(
            FailureStage stage) {
        String primary =
                "merge-atomic-" + stage.suffix + "-primary";
        String secondary =
                "merge-atomic-" + stage.suffix + "-secondary";
        seedUsers(primary, secondary);
        seedCompleteMergeState(primary, secondary);
        PreparedMerge merge = prepareMerge(
                primary,
                secondary,
                "merge-atomic-" + stage.suffix);
        String previewDigest = singleString(
                """
                SELECT preview_digest
                FROM account_merge_intent
                WHERE id = ?
                """,
                merge.intentId());
        installFailureTrigger(stage);
        try {
            assertThatThrownBy(() ->
                    intentService.confirm(
                            merge.actor(),
                            merge.intentId(),
                            merge.previewVersion()))
                    .isInstanceOf(RuntimeException.class);
        } finally {
            removeFailureTrigger(stage);
        }

        assertThat(singleString(
                "SELECT status FROM user_account WHERE id = ?",
                secondary)).isEqualTo("ACTIVE");
        assertThat(singleString(
                """
                SELECT status
                FROM account_merge_intent
                WHERE id = ?
                """,
                merge.intentId())).isEqualTo(
                        "READY_TO_CONFIRM");
        assertThat(dataGateway.inspect(
                primary,
                secondary,
                Instant.now()).digest()).isEqualTo(
                        previewDigest);
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM account_merge_session_revocation
                WHERE merge_intent_id = ?
                """,
                merge.intentId())).isZero();
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM audit_log
                WHERE actor_user_id = ?
                  AND action IN (
                      'ACCOUNT_MERGE_CONFIRMED',
                      'ACCOUNT_MERGE_COMPLETED'
                  )
                """,
                primary)).isZero();
    }

    @Test
    void previewReportsEveryBlockingConflictBeforeAnyMigration() {
        String primary = "merge-conflict-primary";
        String secondary = "merge-conflict-secondary";
        seedUsers(primary, secondary);
        insertActiveBinding(
                primary,
                "conflict-provider",
                "conflict-primary-subject");
        insertActiveBinding(
                secondary,
                "conflict-provider",
                "conflict-secondary-subject");
        jdbcTemplate.update("""
                INSERT INTO user_role_binding (
                    user_id,
                    role_id
                )
                SELECT ?, id
                FROM role
                WHERE code = 'AUDITOR'
                """,
                secondary);
        long namespaceId = insertNamespace(
                "merge-conflict-namespace",
                primary);
        jdbcTemplate.update("""
                INSERT INTO namespace_member (
                    namespace_id,
                    user_id,
                    role
                ) VALUES (?, ?, 'OWNER')
                """,
                namespaceId,
                secondary);
        insertSkill(
                namespaceId,
                "same-coordinate",
                primary);
        insertSkill(
                namespaceId,
                "same-coordinate",
                secondary);
        jdbcTemplate.update("""
                INSERT INTO identity_link_request (
                    id,
                    primary_user_id,
                    operation,
                    provider_code,
                    state_hash,
                    status,
                    expires_at
                ) VALUES (
                    ?,
                    ?,
                    'LINK',
                    'pending-provider',
                    repeat('e', 64),
                    'PENDING_REAUTHENTICATION',
                    CURRENT_TIMESTAMP + INTERVAL '10 minutes'
                )
                """,
                UUID.randomUUID(),
                secondary);
        jdbcTemplate.update("""
                INSERT INTO profile_change_request (
                    user_id,
                    changes,
                    status
                ) VALUES (
                    ?,
                    '{"displayName":"Pending"}'::jsonb,
                    'PENDING'
                )
                """,
                secondary);

        AccountMergeActor actor = actor(
                primary,
                "merge-conflict");
        UUID intentId = UUID.randomUUID();
        intentService.createIntent(actor, intentId);
        intentService.recordSecondaryProof(
                actor,
                intentId,
                secondary,
                "local-password");
        AccountMergePreview preview =
                intentService.preview(actor, intentId);

        assertThat(preview.status()).isEqualTo(
                AccountMergeIntentStatus.FAILED_CONFLICT);
        assertThat(preview.plan().confirmable()).isFalse();
        assertThat(preview.plan().conflicts())
                .extracting(AccountMergePlan.Conflict::code)
                .containsExactlyInAnyOrder(
                        AccountMergePlan.ConflictCode
                                .IDENTITY_PROVIDER_CONFLICT,
                        AccountMergePlan.ConflictCode
                                .PLATFORM_ROLE_CONFLICT,
                        AccountMergePlan.ConflictCode
                                .NAMESPACE_OWNER_CONFLICT,
                        AccountMergePlan.ConflictCode
                                .SKILL_OWNERSHIP_CONFLICT,
                        AccountMergePlan.ConflictCode
                                .ACTIVE_IDENTITY_LINK,
                        AccountMergePlan.ConflictCode
                                .PENDING_PROFILE_CHANGE);
        assertThatThrownBy(() ->
                intentService.confirm(
                        actor,
                        intentId,
                        preview.previewVersion()))
                .isInstanceOfSatisfying(
                        AccountMergeException.class,
                        exception -> assertThat(
                                exception.getReasonCode())
                                .isEqualTo(
                                        AccountMergeFailureCode
                                                .MERGE_PREVIEW_STALE));
        assertThat(singleString(
                "SELECT status FROM user_account WHERE id = ?",
                secondary)).isEqualTo("ACTIVE");
    }

    private PreparedMerge prepareMerge(
            String primary,
            String secondary,
            String noncePrefix) {
        AccountMergeActor actor = actor(
                primary,
                noncePrefix);
        UUID intentId = UUID.randomUUID();
        intentService.createIntent(actor, intentId);
        intentService.recordSecondaryProof(
                actor,
                intentId,
                secondary,
                "local-password");
        AccountMergePreview preview =
                intentService.preview(actor, intentId);
        assertThat(preview.plan().confirmable()).isTrue();
        return new PreparedMerge(
                actor,
                intentId,
                preview.previewVersion());
    }

    private AccountMergeActor actor(
            String primary,
            String noncePrefix) {
        return new AccountMergeActor(
                primary,
                "local",
                noncePrefix + "-high-entropy-session-nonce",
                "local-password",
                Instant.now().minusSeconds(1),
                new IdentityLoginContext(
                        "req-" + noncePrefix,
                        "203.0.113.20",
                        "Account Merge PostgreSQL Test"));
    }

    private SeededResources seedCompleteMergeState(
            String primary,
        String secondary) {
        insertCredentials(primary, secondary);
        insertBindings(secondary);

        long sharedNamespace = insertNamespace(
                primary + "-shared",
                primary);
        long secondaryNamespace = insertNamespace(
                primary + "-secondary-only",
                primary);
        jdbcTemplate.update("""
                INSERT INTO namespace_member (
                    namespace_id,
                    user_id,
                    role
                ) VALUES
                    (?, ?, 'MEMBER'),
                    (?, ?, 'ADMIN'),
                    (?, ?, 'MEMBER')
                """,
                sharedNamespace,
                primary,
                sharedNamespace,
                secondary,
                secondaryNamespace,
                secondary);

        long sharedSkill = insertSkill(
                sharedNamespace,
                "shared-skill",
                primary);
        long secondarySkill = insertSkill(
                sharedNamespace,
                "secondary-skill",
                secondary);
        insertSearchDocument(
                secondarySkill,
                sharedNamespace,
                primary + "-shared",
                secondary);

        jdbcTemplate.update("""
                INSERT INTO skill_star (skill_id, user_id)
                VALUES
                    (?, ?),
                    (?, ?),
                    (?, ?)
                """,
                sharedSkill,
                primary,
                sharedSkill,
                secondary,
                secondarySkill,
                secondary);
        jdbcTemplate.update("""
                INSERT INTO skill_rating (
                    skill_id,
                    user_id,
                    score
                ) VALUES
                    (?, ?, 5),
                    (?, ?, 1),
                    (?, ?, 3)
                """,
                sharedSkill,
                primary,
                sharedSkill,
                secondary,
                secondarySkill,
                secondary);
        jdbcTemplate.update("""
                INSERT INTO skill_subscription (
                    skill_id,
                    user_id
                ) VALUES
                    (?, ?),
                    (?, ?),
                    (?, ?)
                """,
                sharedSkill,
                primary,
                sharedSkill,
                secondary,
                secondarySkill,
                secondary);
        jdbcTemplate.update("""
                UPDATE skill
                SET
                    star_count = CASE
                        WHEN id = ? THEN 2
                        ELSE 1
                    END,
                    rating_count = CASE
                        WHEN id = ? THEN 2
                        ELSE 1
                    END,
                    rating_avg = CASE
                        WHEN id = ? THEN 3.00
                        ELSE 3.00
                    END,
                    subscription_count = CASE
                        WHEN id = ? THEN 2
                        ELSE 1
                    END
                WHERE id IN (?, ?)
                """,
                sharedSkill,
                sharedSkill,
                sharedSkill,
                sharedSkill,
                sharedSkill,
                secondarySkill);

        insertToken(
                secondary,
                "active-secondary-token",
                "active01",
                "a");
        insertToken(
                secondary,
                "already-revoked-token",
                "revoked1",
                "b");
        jdbcTemplate.update("""
                UPDATE api_token
                SET revoked_at = CURRENT_TIMESTAMP
                WHERE user_id = ?
                  AND name = 'already-revoked-token'
                """,
                secondary);
        jdbcTemplate.update("""
                INSERT INTO password_reset_request (
                    user_id,
                    email,
                    code_hash,
                    expires_at
                ) VALUES (
                    ?,
                    'secondary@example.com',
                    'reset-hash',
                    CURRENT_TIMESTAMP + INTERVAL '10 minutes'
                )
                """,
                secondary);
        jdbcTemplate.update("""
                INSERT INTO notification (
                    recipient_id,
                    category,
                    event_type,
                    title
                ) VALUES (?, 'SKILL', 'UPDATED', 'Updated')
                """,
                secondary);
        jdbcTemplate.update("""
                INSERT INTO notification_preference (
                    user_id,
                    category,
                    channel,
                    enabled
                ) VALUES
                    (?, 'SKILL', 'IN_APP', TRUE),
                    (?, 'SKILL', 'IN_APP', FALSE),
                    (?, 'SECURITY', 'IN_APP', TRUE)
                """,
                primary,
                secondary,
                secondary);
        jdbcTemplate.update("""
                INSERT INTO user_notification (
                    user_id,
                    category,
                    entity_type,
                    entity_id,
                    title
                ) VALUES (
                    ?,
                    'GOVERNANCE',
                    'SKILL',
                    ?,
                    'Governance'
                )
                """,
                secondary,
                secondarySkill);
        jdbcTemplate.update("""
                INSERT INTO audit_log (
                    actor_user_id,
                    action,
                    target_type,
                    detail_json
                ) VALUES (
                    ?,
                    'HISTORICAL_ACTION',
                    'USER',
                    '{}'::jsonb
                )
                """,
                secondary);
        return new SeededResources(
                sharedNamespace,
                secondaryNamespace,
                sharedSkill,
                secondarySkill);
    }

    private void seedUsers(
            String primary,
            String secondary) {
        jdbcTemplate.update("""
                INSERT INTO user_account (
                    id,
                    display_name,
                    status
                ) VALUES
                    (?, 'Primary', 'ACTIVE'),
                    (?, 'Secondary', 'ACTIVE')
                """,
                primary,
                secondary);
    }

    private void insertCredentials(
            String primary,
            String secondary) {
        jdbcTemplate.update("""
                INSERT INTO local_credential (
                    user_id,
                    username,
                    password_hash
                ) VALUES
                    (?, ?, 'primary-hash'),
                    (?, ?, 'secondary-hash')
                """,
                primary,
                primary + "-login",
                secondary,
                secondary + "-login");
    }

    private void insertBindings(String secondary) {
        insertActiveBinding(
                secondary,
                "github",
                secondary + "-github-subject");
        new TransactionTemplate(transactionManager)
                .executeWithoutResult(ignored -> {
                    jdbcTemplate.update("""
                            INSERT INTO identity_binding (
                                user_id,
                                provider_code,
                                subject,
                                login_name,
                                status,
                                revoked_at,
                                revoked_by,
                                revocation_reason
                            ) VALUES (
                                ?,
                                'legacy-revoked',
                                ?,
                                'secondary-revoked',
                                'REVOKED',
                                CURRENT_TIMESTAMP,
                                ?,
                                'historical'
                            )
                            """,
                            secondary,
                            secondary + "-revoked-subject",
                            secondary);
                });
    }

    private void insertActiveBinding(
            String userId,
            String providerCode,
            String subject) {
        new TransactionTemplate(transactionManager)
                .executeWithoutResult(ignored -> {
                    Long bindingId = jdbcTemplate.queryForObject(
                            """
                            INSERT INTO identity_binding (
                                user_id,
                                provider_code,
                                subject,
                                login_name,
                                status
                            ) VALUES (
                                ?,
                                ?,
                                ?,
                                ?,
                                'ACTIVE'
                            )
                            RETURNING id
                            """,
                            Long.class,
                            userId,
                            providerCode,
                            subject,
                            userId + "-login");
                    jdbcTemplate.update("""
                            INSERT INTO identity_binding_subject (
                                binding_id,
                                provider_code,
                                subject_type,
                                subject_value,
                                is_primary,
                                status
                            ) VALUES (
                                ?,
                                ?,
                                'provider_subject',
                                ?,
                                TRUE,
                                'ACTIVE'
                            )
                            """,
                            bindingId,
                            providerCode,
                            subject);
                });
    }

    private long insertNamespace(
            String slug,
            String createdBy) {
        Long id = jdbcTemplate.queryForObject(
                """
                INSERT INTO namespace (
                    slug,
                    display_name,
                    type,
                    created_by
                ) VALUES (?, ?, 'TEAM', ?)
                RETURNING id
                """,
                Long.class,
                slug,
                slug,
                createdBy);
        return id == null ? 0L : id;
    }

    private long insertSkill(
            long namespaceId,
            String slug,
            String ownerId) {
        Long id = jdbcTemplate.queryForObject(
                """
                INSERT INTO skill (
                    namespace_id,
                    slug,
                    display_name,
                    owner_id,
                    visibility,
                    status,
                    created_by,
                    updated_by
                ) VALUES (
                    ?,
                    ?,
                    ?,
                    ?,
                    'PUBLIC',
                    'ACTIVE',
                    ?,
                    ?
                )
                RETURNING id
                """,
                Long.class,
                namespaceId,
                slug,
                slug,
                ownerId,
                ownerId,
                ownerId);
        return id == null ? 0L : id;
    }

    private void insertSearchDocument(
            long skillId,
            long namespaceId,
            String namespaceSlug,
            String ownerId) {
        jdbcTemplate.update("""
                INSERT INTO skill_search_document (
                    skill_id,
                    namespace_id,
                    namespace_slug,
                    owner_id,
                    title,
                    visibility,
                    status
                ) VALUES (
                    ?,
                    ?,
                    ?,
                    ?,
                    'Secondary skill',
                    'PUBLIC',
                    'ACTIVE'
                )
                """,
                skillId,
                namespaceId,
                namespaceSlug,
                ownerId);
    }

    private void insertToken(
            String userId,
            String name,
            String prefix,
            String hashCharacter) {
        String tokenHashSource =
                userId + ":" + name + ":" + hashCharacter;
        jdbcTemplate.update("""
                INSERT INTO api_token (
                    subject_type,
                    subject_id,
                    user_id,
                    name,
                    token_prefix,
                    token_hash,
                    scope_json
                ) VALUES (
                    'USER',
                    ?,
                    ?,
                    ?,
                    ?,
                    md5(?) || md5(? || ':2'),
                    '[]'::jsonb
                )
                """,
                userId,
                userId,
                name,
                prefix,
                tokenHashSource,
                tokenHashSource);
    }

    private void installSessionTaskFailureTrigger() {
        jdbcTemplate.execute("""
                CREATE OR REPLACE FUNCTION
                    account_merge_test_fail_session_task()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $$
                BEGIN
                    RAISE EXCEPTION
                        'injected account merge session task failure';
                END;
                $$
                """);
        jdbcTemplate.execute("""
                CREATE TRIGGER
                    account_merge_test_fail_session_task
                BEFORE INSERT
                ON account_merge_session_revocation
                FOR EACH ROW
                EXECUTE FUNCTION
                    account_merge_test_fail_session_task()
                """);
    }

    private void removeSessionTaskFailureTrigger() {
        jdbcTemplate.execute("""
                DROP TRIGGER IF EXISTS
                    account_merge_test_fail_session_task
                ON account_merge_session_revocation
                """);
        jdbcTemplate.execute("""
                DROP FUNCTION IF EXISTS
                    account_merge_test_fail_session_task()
                """);
    }

    private static Stream<FailureStage>
            atomicFailureStages() {
        return Stream.of(FailureStage.values());
    }

    private void installFailureTrigger(
            FailureStage stage) {
        jdbcTemplate.execute("""
                CREATE OR REPLACE FUNCTION
                    account_merge_test_fail_stage()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $$
                BEGIN
                    RAISE EXCEPTION
                        'injected account merge stage failure';
                END;
                $$
                """);
        jdbcTemplate.execute(
                "CREATE TRIGGER "
                        + "account_merge_test_fail_stage "
                        + "BEFORE "
                        + stage.event
                        + " ON "
                        + stage.table
                        + " FOR EACH ROW "
                        + stage.whenClause
                        + " EXECUTE FUNCTION "
                        + "account_merge_test_fail_stage()");
    }

    private void removeFailureTrigger(
            FailureStage stage) {
        jdbcTemplate.execute(
                "DROP TRIGGER IF EXISTS "
                        + "account_merge_test_fail_stage ON "
                        + stage.table);
        jdbcTemplate.execute("""
                DROP FUNCTION IF EXISTS
                    account_merge_test_fail_stage()
                """);
    }

    private long count(String sql, Object... arguments) {
        return singleLong(sql, arguments);
    }

    private long singleLong(
            String sql,
            Object... arguments) {
        Long value = jdbcTemplate.queryForObject(
                sql,
                Long.class,
                arguments);
        return value == null ? 0L : value;
    }

    private String singleString(
            String sql,
            Object... arguments) {
        return jdbcTemplate.queryForObject(
                sql,
                String.class,
                arguments);
    }

    private static String withCurrentSchema(String url) {
        return url + (url.contains("?") ? "&" : "?")
                + "currentSchema="
                + SCHEMA;
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
                    "Failed to create account merge test schema",
                    exception);
        }
    }

    private static String requiredEnvironment(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(
                    "Missing required environment variable "
                            + name);
        }
        return value;
    }

    private record PreparedMerge(
            AccountMergeActor actor,
            UUID intentId,
            int previewVersion) {
    }

    private record SeededResources(
            long sharedNamespaceId,
            long secondaryNamespaceId,
            long sharedSkillId,
            long secondarySkillId) {
    }

    private enum FailureStage {
        BINDING(
                "binding",
                "identity_binding",
                "UPDATE",
                ""),
        CREDENTIAL(
                "credential",
                "local_credential",
                "DELETE",
                ""),
        MEMBERSHIP(
                "membership",
                "namespace_member",
                "DELETE",
                ""),
        BUSINESS_OWNERSHIP(
                "ownership",
                "skill",
                "UPDATE",
                ""),
        TOKEN_REVOCATION(
                "token",
                "api_token",
                "UPDATE",
                ""),
        ACCOUNT_STATUS(
                "account",
                "user_account",
                "UPDATE",
                "WHEN (NEW.status = 'MERGED')"),
        INTENT_STATUS(
                "intent",
                "account_merge_intent",
                "UPDATE",
                "WHEN (NEW.status = 'COMPLETED')"),
        COMPLETION_AUDIT(
                "audit",
                "audit_log",
                "INSERT",
                "WHEN (NEW.action = "
                        + "'ACCOUNT_MERGE_COMPLETED')");

        private final String suffix;
        private final String table;
        private final String event;
        private final String whenClause;

        FailureStage(
                String suffix,
                String table,
                String event,
                String whenClause) {
            this.suffix = suffix;
            this.table = table;
            this.event = event;
            this.whenClause = whenClause;
        }
    }
}
