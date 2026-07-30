package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

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

    private static final String PREFLIGHT_SCHEMA =
            "identity_v2_expand_preflight";

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
                .target(MigrationVersion.fromVersion("45"))
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
                        'legacy_subject',
                        subject,
                        FALSE,
                        'ACTIVE',
                        created_at,
                        updated_at
                    FROM identity_binding
                    WHERE user_id =
                        'identity-v2-mixed-version-user'
                    UNION ALL
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
                    WHERE user_id =
                        'identity-v2-mixed-version-user'
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
                      AND subject.status = 'ACTIVE'
                    """)).isEqualTo(2L);
        }
    }

    @Test
    void preflightReportsAllUnsafeLegacyBindingClasses()
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
                    .schemas(PREFLIGHT_SCHEMA)
                    .defaultSchema(PREFLIGHT_SCHEMA)
                    .createSchemas(true)
                    .target(MigrationVersion.fromVersion("45"))
                    .load()
                    .migrate();

            try (Connection connection = DriverManager.getConnection(
                    url,
                    username,
                    password);
                    Statement statement = connection.createStatement()) {
                statement.execute(
                        "SET search_path TO " + PREFLIGHT_SCHEMA);
                statement.executeUpdate("""
                        INSERT INTO user_account (
                            id,
                            display_name,
                            status,
                            created_at,
                            updated_at
                        ) VALUES
                            ('identity-v2-duplicate-user',
                             'Duplicate User',
                             'ACTIVE',
                             CURRENT_TIMESTAMP,
                             CURRENT_TIMESTAMP),
                            ('identity-v2-merged-user',
                             'Merged User',
                             'MERGED',
                             CURRENT_TIMESTAMP,
                             CURRENT_TIMESTAMP),
                            ('identity-v2-invalid-user',
                             'Invalid Identifier User',
                             'ACTIVE',
                             CURRENT_TIMESTAMP,
                             CURRENT_TIMESTAMP)
                        """);
                statement.executeUpdate("""
                        INSERT INTO identity_binding (
                            user_id,
                            provider_code,
                            subject,
                            login_name,
                            created_at,
                            updated_at
                        ) VALUES
                            ('identity-v2-duplicate-user',
                             'github',
                             '910000000001',
                             'duplicate-one',
                             CURRENT_TIMESTAMP,
                             CURRENT_TIMESTAMP),
                            ('identity-v2-duplicate-user',
                             'github',
                             '910000000002',
                             'duplicate-two',
                             CURRENT_TIMESTAMP,
                             CURRENT_TIMESTAMP),
                            ('identity-v2-merged-user',
                             'gitlab',
                             '920000000001',
                             'merged',
                             CURRENT_TIMESTAMP,
                             CURRENT_TIMESTAMP),
                            ('identity-v2-invalid-user',
                             'Invalid Provider',
                             '   ',
                             'invalid',
                             CURRENT_TIMESTAMP,
                             CURRENT_TIMESTAMP)
                        """);
            }

            Throwable failure = catchThrowable(() ->
                    Flyway.configure()
                            .dataSource(url, username, password)
                            .locations("classpath:db/migration")
                            .schemas(PREFLIGHT_SCHEMA)
                            .defaultSchema(PREFLIGHT_SCHEMA)
                            .createSchemas(true)
                            .target(MigrationVersion.fromVersion("46"))
                            .load()
                            .migrate());

            assertThat(failure).isNotNull();
            assertThat(rootCause(failure).getMessage())
                    .contains(
                            "multiple active bindings for user/provider")
                    .contains(
                            "bindings reference missing or MERGED accounts")
                    .contains(
                            "bindings contain invalid provider/subject identifiers");

            try (Connection connection = DriverManager.getConnection(
                    url,
                    username,
                    password);
                    Statement statement = connection.createStatement()) {
                statement.execute(
                        "SET search_path TO " + PREFLIGHT_SCHEMA);
                assertThat(singleString(
                        statement,
                        """
                        SELECT version
                        FROM flyway_schema_history
                        WHERE success = TRUE
                        ORDER BY installed_rank DESC
                        LIMIT 1
                        """)).isEqualTo("45");
                assertThat(singleLong(
                        statement,
                        """
                        SELECT COUNT(*)
                        FROM information_schema.columns
                        WHERE table_schema =
                            'identity_v2_expand_preflight'
                          AND table_name = 'identity_binding'
                          AND column_name = 'status'
                        """)).isZero();
            }
        } finally {
            dropSchema(url, username, password);
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

    private static void dropSchema(
            String url,
            String username,
            String password) throws Exception {
        try (Connection connection = DriverManager.getConnection(
                url,
                username,
                password);
                Statement statement = connection.createStatement()) {
            statement.execute(
                    "DROP SCHEMA IF EXISTS "
                            + PREFLIGHT_SCHEMA
                            + " CASCADE");
        }
    }

    private static Throwable rootCause(Throwable failure) {
        Throwable current = failure;
        while (current.getCause() != null
                && current.getCause() != current) {
            current = current.getCause();
        }
        return current;
    }
}
