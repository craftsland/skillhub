package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;

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
class IdentityLinkMigrationPostgresTest {

    private static final String SCHEMA =
            "identity_link_v49_migration";

    @Test
    void upgradesExistingBindingsAndAllowsRelinkAfterRevocation()
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
                    .target(MigrationVersion.fromVersion("48"))
                    .load()
                    .migrate();

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
                            email,
                            status,
                            created_at,
                            updated_at
                        ) VALUES (
                            'identity-link-upgrade-user',
                            'Identity Link Upgrade User',
                            'identity-link-upgrade@example.com',
                            'ACTIVE',
                            CURRENT_TIMESTAMP,
                            CURRENT_TIMESTAMP
                        )
                        """);
                statement.executeUpdate("""
                        INSERT INTO identity_provider_state (
                            provider_code,
                            protocol,
                            authority,
                            authority_fingerprint,
                            state
                        ) VALUES (
                            'github',
                            'oauth2-github',
                            'https://github.com',
                            repeat('a', 64),
                            'READY'
                        )
                        """);
                connection.setAutoCommit(false);
                statement.executeUpdate("""
                        INSERT INTO identity_binding (
                            user_id,
                            provider_code,
                            subject,
                            login_name,
                            status,
                            created_at,
                            updated_at
                        ) VALUES (
                            'identity-link-upgrade-user',
                            'github',
                            '6554901',
                            'identity-link-upgrade',
                            'ACTIVE',
                            CURRENT_TIMESTAMP,
                            CURRENT_TIMESTAMP
                        )
                        """);
                statement.executeUpdate("""
                        INSERT INTO identity_binding_subject (
                            binding_id,
                            provider_code,
                            subject_type,
                            subject_value,
                            is_primary,
                            status,
                            created_at,
                            last_seen_at
                        )
                        SELECT
                            id,
                            provider_code,
                            'github_user_id',
                            subject,
                            TRUE,
                            'ACTIVE',
                            created_at,
                            updated_at
                        FROM identity_binding
                        WHERE user_id = 'identity-link-upgrade-user'
                        """);
                connection.commit();
            }

            Flyway.configure()
                    .dataSource(url, username, password)
                    .locations("classpath:db/migration")
                    .schemas(SCHEMA)
                    .defaultSchema(SCHEMA)
                    .createSchemas(true)
                    .target(MigrationVersion.fromVersion("49"))
                    .load()
                    .migrate();

            try (Connection connection =
                    DriverManager.getConnection(
                            url,
                            username,
                            password);
                    Statement statement =
                            connection.createStatement()) {
                statement.execute("SET search_path TO " + SCHEMA);
                assertThat(singleLong(
                        statement,
                        """
                        SELECT COUNT(*)
                        FROM identity_binding
                        WHERE user_id = 'identity-link-upgrade-user'
                          AND provider_code = 'github'
                          AND subject = '6554901'
                          AND status = 'ACTIVE'
                        """)).isEqualTo(1L);
                assertThat(singleLong(
                        statement,
                        """
                        SELECT COUNT(*)
                        FROM information_schema.tables
                        WHERE table_schema = 'identity_link_v49_migration'
                          AND table_name = 'identity_link_request'
                        """)).isEqualTo(1L);
                assertThat(singleLong(
                        statement,
                        """
                        SELECT COUNT(*)
                        FROM pg_indexes
                        WHERE schemaname = 'identity_link_v49_migration'
                          AND indexname =
                              'uq_identity_binding_active_provider_subject'
                        """)).isEqualTo(1L);

                connection.setAutoCommit(false);
                statement.executeUpdate("""
                        UPDATE identity_binding_subject
                        SET
                            is_primary = FALSE,
                            status = 'REVOKED',
                            revoked_at = CURRENT_TIMESTAMP
                        WHERE provider_code = 'github'
                          AND subject_value = '6554901'
                          AND status = 'ACTIVE'
                        """);
                statement.executeUpdate("""
                        UPDATE identity_binding
                        SET
                            status = 'REVOKED',
                            revoked_at = CURRENT_TIMESTAMP,
                            revoked_by = 'identity-link-upgrade-user',
                            revocation_reason = 'migration test'
                        WHERE provider_code = 'github'
                          AND subject = '6554901'
                          AND status = 'ACTIVE'
                        """);
                statement.executeUpdate("""
                        INSERT INTO identity_binding (
                            user_id,
                            provider_code,
                            subject,
                            login_name,
                            status,
                            created_at,
                            updated_at
                        ) VALUES (
                            'identity-link-upgrade-user',
                            'github',
                            '6554901',
                            'identity-link-upgrade',
                            'ACTIVE',
                            CURRENT_TIMESTAMP,
                            CURRENT_TIMESTAMP
                        )
                        """);
                statement.executeUpdate("""
                        INSERT INTO identity_binding_subject (
                            binding_id,
                            provider_code,
                            subject_type,
                            subject_value,
                            is_primary,
                            status,
                            created_at,
                            last_seen_at
                        )
                        SELECT
                            id,
                            provider_code,
                            'github_user_id',
                            subject,
                            TRUE,
                            'ACTIVE',
                            created_at,
                            updated_at
                        FROM identity_binding
                        WHERE user_id = 'identity-link-upgrade-user'
                          AND provider_code = 'github'
                          AND subject = '6554901'
                          AND status = 'ACTIVE'
                        """);
                connection.commit();

                assertThat(singleLong(
                        statement,
                        """
                        SELECT COUNT(*)
                        FROM identity_binding
                        WHERE provider_code = 'github'
                          AND subject = '6554901'
                          AND status = 'ACTIVE'
                        """)).isEqualTo(1L);
                assertThat(singleLong(
                        statement,
                        """
                        SELECT COUNT(*)
                        FROM identity_binding
                        WHERE provider_code = 'github'
                          AND subject = '6554901'
                          AND status = 'REVOKED'
                        """)).isEqualTo(1L);
            }
        } finally {
            dropSchema(url, username, password);
        }
    }

    private static long singleLong(
            Statement statement,
            String sql) throws Exception {
        try (ResultSet result = statement.executeQuery(sql)) {
            assertThat(result.next()).isTrue();
            return result.getLong(1);
        }
    }

    private static String requiredEnvironment(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(
                    "Missing required environment variable " + name);
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
