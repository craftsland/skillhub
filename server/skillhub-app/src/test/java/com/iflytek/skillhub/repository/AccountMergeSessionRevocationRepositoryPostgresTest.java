package com.iflytek.skillhub.repository;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

@EnabledIfEnvironmentVariable(
        named = "IDENTITY_BINDING_V2_POSTGRES_URL",
        matches = "jdbc:postgresql:.*")
class AccountMergeSessionRevocationRepositoryPostgresTest {

    private static final String SCHEMA =
            "account_merge_session_revocation_repository";
    private static final Instant NOW =
            Instant.parse("2026-07-31T10:00:00Z");

    @Test
    void claimsCompletesAndRetriesOnlyDueLeases()
            throws Exception {
        String url = requiredEnvironment(
                "IDENTITY_BINDING_V2_POSTGRES_URL");
        String username = requiredEnvironment(
                "IDENTITY_BINDING_V2_POSTGRES_USERNAME");
        String password = requiredEnvironment(
                "IDENTITY_BINDING_V2_POSTGRES_PASSWORD");
        dropSchema(url, username, password);
        try {
            Flyway.configure()
                    .dataSource(url, username, password)
                    .locations("classpath:db/migration")
                    .schemas(SCHEMA)
                    .defaultSchema(SCHEMA)
                    .createSchemas(true)
                    .load()
                    .migrate();
            seed(url, username, password);
            AccountMergeSessionRevocationRepository repository =
                    repository(url, username, password);

            var first = repository.claimNext(
                    NOW,
                    Duration.ofMinutes(2)).orElseThrow();
            assertThat(first.id()).isEqualTo(1L);
            assertThat(first.attemptCount()).isEqualTo(1);
            assertThat(repository.complete(first, NOW))
                    .isTrue();

            var reclaimed = repository.claimNext(
                    NOW,
                    Duration.ofMinutes(2)).orElseThrow();
            assertThat(reclaimed.id()).isEqualTo(3L);
            assertThat(reclaimed.attemptCount()).isEqualTo(5);
            assertThat(repository.retry(
                    reclaimed,
                    NOW.plusSeconds(80),
                    "SESSION_STORE_FAILURE",
                    NOW)).isTrue();

            assertThat(repository.claimNext(
                    NOW,
                    Duration.ofMinutes(2))).isEmpty();
            assertState(
                    url,
                    username,
                    password);
        } finally {
            dropSchema(url, username, password);
        }
    }

    private static AccountMergeSessionRevocationRepository
            repository(
                    String url,
                    String username,
                    String password) {
        DriverManagerDataSource dataSource =
                new DriverManagerDataSource(
                        schemaUrl(url),
                        username,
                        password);
        return new AccountMergeSessionRevocationRepository(
                new JdbcTemplate(dataSource));
    }

    private static void seed(
            String url,
            String username,
            String password) throws Exception {
        try (Connection connection =
                DriverManager.getConnection(
                        url,
                        username,
                        password);
                Statement statement =
                        connection.createStatement()) {
            statement.execute("SET search_path TO " + SCHEMA);
            statement.executeUpdate("""
                    INSERT INTO user_account (
                        id,
                        display_name,
                        status,
                        created_at,
                        updated_at
                    ) VALUES
                        (
                            'merge-primary',
                            'Merge Primary',
                            'ACTIVE',
                            CURRENT_TIMESTAMP,
                            CURRENT_TIMESTAMP
                        ),
                        (
                            'merge-secondary',
                            'Merge Secondary',
                            'MERGED',
                            CURRENT_TIMESTAMP,
                            CURRENT_TIMESTAMP
                        )
                    """);
            statement.executeUpdate("""
                    INSERT INTO account_merge_intent (
                        id,
                        primary_user_id,
                        secondary_user_id,
                        status,
                        primary_session_nonce_hash,
                        primary_proof_method,
                        primary_proof_at,
                        secondary_proof_method,
                        secondary_proof_at,
                        expires_at,
                        completed_at
                    ) VALUES (
                        '03ea32a0-f0bf-4b3c-966c-bca7bb58381b',
                        'merge-primary',
                        'merge-secondary',
                        'COMPLETED',
                        repeat('a', 64),
                        'local-password',
                        TIMESTAMPTZ '2026-07-31 09:55:00Z',
                        'provider:github',
                        TIMESTAMPTZ '2026-07-31 09:56:00Z',
                        TIMESTAMPTZ '2026-07-31 10:05:00Z',
                        TIMESTAMPTZ '2026-07-31 09:59:00Z'
                    )
                    """);
            statement.executeUpdate("""
                    INSERT INTO account_merge_session_revocation (
                        merge_intent_id,
                        user_id,
                        status,
                        attempt_count,
                        next_attempt_at,
                        lease_until,
                        created_at,
                        updated_at
                    ) VALUES
                        (
                            '03ea32a0-f0bf-4b3c-966c-bca7bb58381b',
                            'merge-secondary',
                            'PENDING',
                            0,
                            TIMESTAMPTZ '2026-07-31 09:59:00Z',
                            NULL,
                            CURRENT_TIMESTAMP,
                            CURRENT_TIMESTAMP
                        )
                    """);
            statement.executeUpdate("""
                    INSERT INTO account_merge_intent (
                        id,
                        primary_user_id,
                        secondary_user_id,
                        status,
                        primary_session_nonce_hash,
                        primary_proof_method,
                        primary_proof_at,
                        secondary_proof_method,
                        secondary_proof_at,
                        expires_at,
                        completed_at
                    ) VALUES
                        (
                            '13ea32a0-f0bf-4b3c-966c-bca7bb58381b',
                            'merge-primary',
                            'merge-secondary',
                            'COMPLETED',
                            repeat('b', 64),
                            'local-password',
                            TIMESTAMPTZ '2026-07-31 09:55:00Z',
                            'provider:github',
                            TIMESTAMPTZ '2026-07-31 09:56:00Z',
                            TIMESTAMPTZ '2026-07-31 10:05:00Z',
                            TIMESTAMPTZ '2026-07-31 09:59:00Z'
                        ),
                        (
                            '23ea32a0-f0bf-4b3c-966c-bca7bb58381b',
                            'merge-primary',
                            'merge-secondary',
                            'COMPLETED',
                            repeat('c', 64),
                            'local-password',
                            TIMESTAMPTZ '2026-07-31 09:55:00Z',
                            'provider:github',
                            TIMESTAMPTZ '2026-07-31 09:56:00Z',
                            TIMESTAMPTZ '2026-07-31 10:05:00Z',
                            TIMESTAMPTZ '2026-07-31 09:59:00Z'
                        )
                    """);
            statement.executeUpdate("""
                    INSERT INTO account_merge_session_revocation (
                        merge_intent_id,
                        user_id,
                        status,
                        attempt_count,
                        next_attempt_at,
                        lease_until,
                        created_at,
                        updated_at
                    ) VALUES
                        (
                            '13ea32a0-f0bf-4b3c-966c-bca7bb58381b',
                            'merge-secondary',
                            'PENDING',
                            0,
                            TIMESTAMPTZ '2026-07-31 11:00:00Z',
                            NULL,
                            CURRENT_TIMESTAMP,
                            CURRENT_TIMESTAMP
                        ),
                        (
                            '23ea32a0-f0bf-4b3c-966c-bca7bb58381b',
                            'merge-secondary',
                            'PROCESSING',
                            4,
                            TIMESTAMPTZ '2026-07-31 09:00:00Z',
                            TIMESTAMPTZ '2026-07-31 09:59:00Z',
                            CURRENT_TIMESTAMP,
                            CURRENT_TIMESTAMP
                        )
                    """);
        }
    }

    private static void assertState(
            String url,
            String username,
            String password) throws Exception {
        try (Connection connection =
                DriverManager.getConnection(
                        url,
                        username,
                        password);
                Statement statement =
                        connection.createStatement()) {
            statement.execute("SET search_path TO " + SCHEMA);
            try (ResultSet result = statement.executeQuery("""
                    SELECT id,
                           status,
                           attempt_count,
                           last_error_code
                    FROM account_merge_session_revocation
                    ORDER BY id
                    """)) {
                assertThat(result.next()).isTrue();
                assertThat(result.getString("status"))
                        .isEqualTo("COMPLETED");
                assertThat(result.getInt("attempt_count"))
                        .isEqualTo(1);
                assertThat(result.next()).isTrue();
                assertThat(result.getString("status"))
                        .isEqualTo("PENDING");
                assertThat(result.getInt("attempt_count"))
                        .isZero();
                assertThat(result.next()).isTrue();
                assertThat(result.getString("status"))
                        .isEqualTo("PENDING");
                assertThat(result.getInt("attempt_count"))
                        .isEqualTo(5);
                assertThat(result.getString("last_error_code"))
                        .isEqualTo("SESSION_STORE_FAILURE");
                assertThat(result.next()).isFalse();
            }
        }
    }

    private static String schemaUrl(String url) {
        return url + (url.contains("?") ? "&" : "?")
                + "currentSchema="
                + SCHEMA;
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

    private static void dropSchema(
            String url,
            String username,
            String password) throws Exception {
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
        }
    }
}
