package com.iflytek.skillhub.auth.merge;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

@EnabledIfEnvironmentVariable(
        named = "IDENTITY_BINDING_V2_POSTGRES_URL",
        matches = "jdbc:postgresql:.*")
class AccountMergeIntentMigrationPostgresTest {

    private static final String SCHEMA =
            "account_merge_v50_migration";

    @Test
    void upgradesAdditivelyAndLeavesLegacyRequestsIsolated()
            throws Exception {
        String url = requiredEnvironment(
                "IDENTITY_BINDING_V2_POSTGRES_URL");
        String username = requiredEnvironment(
                "IDENTITY_BINDING_V2_POSTGRES_USERNAME");
        String password = requiredEnvironment(
                "IDENTITY_BINDING_V2_POSTGRES_PASSWORD");
        dropSchema(url, username, password);
        try {
            migrateTo(url, username, password, "49");
            try (Connection connection =
                    DriverManager.getConnection(
                            url,
                            username,
                            password);
                    Statement statement =
                            connection.createStatement()) {
                statement.execute(
                        "SET search_path TO " + SCHEMA);
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
                                'ACTIVE',
                                CURRENT_TIMESTAMP,
                                CURRENT_TIMESTAMP
                            )
                        """);
                statement.executeUpdate("""
                        INSERT INTO account_merge_request (
                            primary_user_id,
                            secondary_user_id,
                            status,
                            verification_token,
                            token_expires_at,
                            created_at
                        ) VALUES (
                            'merge-primary',
                            'merge-secondary',
                            'VERIFIED',
                            'legacy-proof-must-not-migrate',
                            CURRENT_TIMESTAMP
                                + INTERVAL '10 minutes',
                            CURRENT_TIMESTAMP
                        )
                        """);
            }

            migrateTo(url, username, password, "50");
            try (Connection connection =
                    DriverManager.getConnection(
                            url,
                            username,
                            password);
                    Statement statement =
                            connection.createStatement()) {
                statement.execute(
                        "SET search_path TO " + SCHEMA);
                assertThat(singleLong(
                        statement,
                        """
                        SELECT COUNT(*)
                        FROM account_merge_request
                        WHERE primary_user_id = 'merge-primary'
                          AND secondary_user_id = 'merge-secondary'
                          AND status = 'VERIFIED'
                          AND verification_token =
                              'legacy-proof-must-not-migrate'
                        """)).isEqualTo(1L);
                assertThat(singleLong(
                        statement,
                        """
                        SELECT COUNT(*)
                        FROM account_merge_intent
                        """)).isZero();

                statement.executeUpdate("""
                        INSERT INTO account_merge_intent (
                            id,
                            primary_user_id,
                            status,
                            primary_session_nonce_hash,
                            primary_proof_method,
                            primary_proof_at,
                            expires_at
                        ) VALUES (
                            '03ea32a0-f0bf-4b3c-966c-bca7bb58381b',
                            'merge-primary',
                            'PENDING_SECONDARY_PROOF',
                            repeat('a', 64),
                            'local-password',
                            CURRENT_TIMESTAMP,
                            CURRENT_TIMESTAMP
                                + INTERVAL '10 minutes'
                        )
                        """);

                assertThatThrownBy(() ->
                        statement.executeUpdate("""
                                INSERT INTO account_merge_intent (
                                    id,
                                    primary_user_id,
                                    status,
                                    primary_session_nonce_hash,
                                    primary_proof_method,
                                    primary_proof_at,
                                    expires_at
                                ) VALUES (
                                    'ff911729-6741-4290-908a-5b0ef64191fb',
                                    'merge-primary',
                                    'PENDING_SECONDARY_PROOF',
                                    repeat('b', 64),
                                    'local-password',
                                    CURRENT_TIMESTAMP,
                                    CURRENT_TIMESTAMP
                                        + INTERVAL '10 minutes'
                                )
                                """))
                        .hasMessageContaining(
                                "uq_account_merge_intent_active_primary");

                assertThatThrownBy(() ->
                        statement.executeUpdate("""
                                UPDATE account_merge_intent
                                SET
                                    secondary_user_id =
                                        primary_user_id,
                                    secondary_proof_method =
                                        'local-password',
                                    secondary_proof_at =
                                        CURRENT_TIMESTAMP,
                                    status = 'READY_FOR_PREVIEW'
                                WHERE id =
                                    '03ea32a0-f0bf-4b3c-966c-bca7bb58381b'
                                """))
                        .hasMessageContaining(
                                "chk_account_merge_intent_distinct_users");
            }
        } finally {
            dropSchema(url, username, password);
        }
    }

    private static void migrateTo(
            String url,
            String username,
            String password,
            String version) {
        Flyway.configure()
                .dataSource(url, username, password)
                .locations("classpath:db/migration")
                .schemas(SCHEMA)
                .defaultSchema(SCHEMA)
                .createSchemas(true)
                .target(MigrationVersion.fromVersion(version))
                .load()
                .migrate();
    }

    private static long singleLong(
            Statement statement,
            String sql) throws Exception {
        try (ResultSet result =
                statement.executeQuery(sql)) {
            assertThat(result.next()).isTrue();
            return result.getLong(1);
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
