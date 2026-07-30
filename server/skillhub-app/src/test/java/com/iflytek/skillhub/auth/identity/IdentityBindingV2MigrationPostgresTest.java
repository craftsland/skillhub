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
class IdentityBindingV2MigrationPostgresTest {

    static final String PRE_EXPAND_USER =
            "identity-v2-pre-expand-user";
    static final String PRE_EXPAND_SUBJECT =
            "900000000001";
    static final String MIXED_VERSION_USER =
            "identity-v2-mixed-version-user";
    static final String MIXED_VERSION_SUBJECT =
            "900000000002";

    @Test
    void migratesLegacyDataAndKeepsOldWritesValidDuringExpand() throws Exception {
        String url = requiredEnvironment(
                "IDENTITY_BINDING_V2_POSTGRES_URL");
        String username = requiredEnvironment(
                "IDENTITY_BINDING_V2_POSTGRES_USERNAME");
        String password = requiredEnvironment(
                "IDENTITY_BINDING_V2_POSTGRES_PASSWORD");

        Flyway.configure()
                .dataSource(url, username, password)
                .locations("classpath:db/migration")
                .target(MigrationVersion.fromVersion("44"))
                .load()
                .migrate();

        try (Connection connection =
                DriverManager.getConnection(
                        url,
                        username,
                        password);
                Statement statement =
                        connection.createStatement()) {
            statement.executeUpdate("""
                    INSERT INTO user_account (
                        id,
                        display_name,
                        email,
                        status,
                        created_at,
                        updated_at
                    ) VALUES (
                        'identity-v2-pre-expand-user',
                        'Pre Expand User',
                        'pre-expand@example.com',
                        'ACTIVE',
                        CURRENT_TIMESTAMP,
                        CURRENT_TIMESTAMP
                    )
                    """);
            statement.executeUpdate("""
                    INSERT INTO identity_binding (
                        user_id,
                        provider_code,
                        subject,
                        login_name,
                        created_at,
                        updated_at
                    ) VALUES (
                        'identity-v2-pre-expand-user',
                        'github',
                        '900000000001',
                        'pre-expand',
                        CURRENT_TIMESTAMP,
                        CURRENT_TIMESTAMP
                    )
                    """);
        }

        Flyway.configure()
                .dataSource(url, username, password)
                .locations("classpath:db/migration")
                .load()
                .migrate();

        try (Connection connection =
                DriverManager.getConnection(
                        url,
                        username,
                        password);
                Statement statement =
                        connection.createStatement()) {
            assertThat(singleString(
                    statement,
                    """
                    SELECT status
                    FROM identity_binding
                    WHERE user_id = 'identity-v2-pre-expand-user'
                    """)).isEqualTo("ACTIVE");
            assertThat(singleLong(
                    statement,
                    """
                    SELECT COUNT(*)
                    FROM identity_binding_subject subject
                    JOIN identity_binding binding
                      ON binding.id = subject.binding_id
                    WHERE binding.user_id =
                        'identity-v2-pre-expand-user'
                      AND subject.subject_type = 'legacy_subject'
                      AND subject.subject_value = '900000000001'
                      AND subject.is_primary = TRUE
                      AND subject.status = 'ACTIVE'
                    """)).isEqualTo(1L);

            statement.executeUpdate("""
                    INSERT INTO user_account (
                        id,
                        display_name,
                        email,
                        status,
                        created_at,
                        updated_at
                    ) VALUES (
                        'identity-v2-mixed-version-user',
                        'Mixed Version User',
                        'mixed-version@example.com',
                        'ACTIVE',
                        CURRENT_TIMESTAMP,
                        CURRENT_TIMESTAMP
                    )
                    """);
            statement.executeUpdate("""
                    INSERT INTO identity_binding (
                        user_id,
                        provider_code,
                        subject,
                        login_name,
                        created_at,
                        updated_at
                    ) VALUES (
                        'identity-v2-mixed-version-user',
                        'github',
                        '900000000002',
                        'mixed-version',
                        CURRENT_TIMESTAMP,
                        CURRENT_TIMESTAMP
                    )
                    """);
            assertThat(singleLong(
                    statement,
                    """
                    SELECT COUNT(*)
                    FROM identity_binding_subject subject
                    JOIN identity_binding binding
                      ON binding.id = subject.binding_id
                    WHERE binding.user_id =
                        'identity-v2-mixed-version-user'
                    """)).isZero();
        }
    }

    private static String singleString(
            Statement statement,
            String sql) throws Exception {
        try (ResultSet result = statement.executeQuery(sql)) {
            assertThat(result.next()).isTrue();
            return result.getString(1);
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
}
