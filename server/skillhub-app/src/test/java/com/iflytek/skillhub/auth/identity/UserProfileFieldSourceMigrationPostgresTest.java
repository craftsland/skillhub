package com.iflytek.skillhub.auth.identity;

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
class UserProfileFieldSourceMigrationPostgresTest {

    private static final String SCHEMA =
            "identity_profile_v47_migration";

    @Test
    void backfillsLegacyFieldsAndEnforcesSourceMetadata()
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
                    .target(MigrationVersion.fromVersion("46"))
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
                            avatar_url,
                            status,
                            created_at,
                            updated_at
                        ) VALUES
                            (
                                'legacy-complete',
                                'Legacy Complete',
                                'legacy@example.com',
                                'https://example.com/avatar.png',
                                'ACTIVE',
                                CURRENT_TIMESTAMP,
                                CURRENT_TIMESTAMP
                            ),
                            (
                                'legacy-minimal',
                                'Legacy Minimal',
                                NULL,
                                NULL,
                                'ACTIVE',
                                CURRENT_TIMESTAMP,
                                CURRENT_TIMESTAMP
                            )
                        """);
            }

            Flyway.configure()
                    .dataSource(url, username, password)
                    .locations("classpath:db/migration")
                    .schemas(SCHEMA)
                    .defaultSchema(SCHEMA)
                    .createSchemas(true)
                    .target(MigrationVersion.fromVersion("47"))
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
                        FROM user_profile_field_source
                        WHERE user_id = 'legacy-complete'
                          AND source_type = 'LEGACY_LOCAL'
                          AND provider_code IS NULL
                          AND assurance IS NULL
                          AND last_synchronized_at IS NULL
                        """)).isEqualTo(3L);
                assertThat(singleLong(
                        statement,
                        """
                        SELECT COUNT(*)
                        FROM user_profile_field_source
                        WHERE user_id = 'legacy-minimal'
                          AND field_name = 'displayName'
                          AND source_type = 'LEGACY_LOCAL'
                        """)).isEqualTo(1L);

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
                statement.executeUpdate("""
                        UPDATE user_profile_field_source
                        SET
                            source_type = 'PROVIDER',
                            provider_code = 'github',
                            assurance = 'VERIFIED',
                            last_synchronized_at = CURRENT_TIMESTAMP
                        WHERE user_id = 'legacy-complete'
                          AND field_name = 'email'
                        """);
                assertThat(singleLong(
                        statement,
                        """
                        SELECT COUNT(*)
                        FROM user_profile_field_source
                        WHERE user_id = 'legacy-complete'
                          AND field_name = 'email'
                          AND source_type = 'PROVIDER'
                          AND provider_code = 'github'
                          AND assurance = 'VERIFIED'
                        """)).isEqualTo(1L);

                assertThatThrownBy(() -> statement.executeUpdate("""
                        UPDATE user_profile_field_source
                        SET
                            source_type = 'USER',
                            provider_code = 'github'
                        WHERE user_id = 'legacy-complete'
                          AND field_name = 'avatarUrl'
                        """)).hasMessageContaining(
                                "chk_user_profile_field_provider_source");

                statement.executeUpdate("""
                        DELETE FROM user_account
                        WHERE id = 'legacy-minimal'
                        """);
                assertThat(singleLong(
                        statement,
                        """
                        SELECT COUNT(*)
                        FROM user_profile_field_source
                        WHERE user_id = 'legacy-minimal'
                        """)).isZero();
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
