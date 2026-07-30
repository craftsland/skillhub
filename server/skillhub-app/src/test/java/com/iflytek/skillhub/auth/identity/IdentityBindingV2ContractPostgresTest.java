package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

@EnabledIfEnvironmentVariable(
        named = "IDENTITY_BINDING_V2_POSTGRES_URL",
        matches = "jdbc:postgresql:.*")
class IdentityBindingV2ContractPostgresTest {

    private static final String PREFLIGHT_SCHEMA =
            "identity_v2_contract_preflight";

    @Test
    void contractMigrationRejectsActiveBindingWithoutPrimary()
            throws Exception {
        Database database = database();
        dropSchema(database, PREFLIGHT_SCHEMA);
        try {
            Flyway.configure()
                    .dataSource(
                            database.url(),
                            database.username(),
                            database.password())
                    .locations("classpath:db/migration")
                    .schemas(PREFLIGHT_SCHEMA)
                    .defaultSchema(PREFLIGHT_SCHEMA)
                    .createSchemas(true)
                    .target(MigrationVersion.fromVersion("46"))
                    .load()
                    .migrate();

            try (Connection connection = database.connect();
                    Statement statement = connection.createStatement()) {
                statement.execute(
                        "SET search_path TO " + PREFLIGHT_SCHEMA);
                insertUser(statement, "contract-preflight-user");
                statement.executeUpdate("""
                        INSERT INTO identity_binding (
                            user_id,
                            provider_code,
                            subject,
                            login_name,
                            created_at,
                            updated_at
                        ) VALUES (
                            'contract-preflight-user',
                            'contract-provider',
                            'contract-preflight-subject',
                            'contract-preflight',
                            CURRENT_TIMESTAMP,
                            CURRENT_TIMESTAMP
                        )
                        """);
            }

            Throwable failure = catchThrowable(() ->
                    Flyway.configure()
                            .dataSource(
                                    database.url(),
                                    database.username(),
                                    database.password())
                            .locations("classpath:db/migration")
                            .schemas(PREFLIGHT_SCHEMA)
                            .defaultSchema(PREFLIGHT_SCHEMA)
                            .createSchemas(true)
                            .load()
                            .migrate());

            assertThat(failure).isNotNull();
            assertThat(rootCause(failure).getMessage())
                    .contains(
                            "Binding V2 contract preflight failed");

            try (Connection connection = database.connect();
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
                        """)).isEqualTo("46");
                assertThat(singleLong(
                        statement,
                        """
                        SELECT COUNT(*)
                        FROM pg_trigger trigger
                        JOIN pg_class relation
                          ON relation.oid = trigger.tgrelid
                        JOIN pg_namespace namespace
                          ON namespace.oid = relation.relnamespace
                        WHERE namespace.nspname =
                            'identity_v2_contract_preflight'
                          AND trigger.tgname =
                            'ct_identity_binding_active_primary'
                        """)).isZero();
            }
        } finally {
            dropSchema(database, PREFLIGHT_SCHEMA);
        }
    }

    @Test
    void contractGateEnforcesExactlyOnePrimaryAndAtomicReplacement()
            throws Exception {
        Database database = database();
        Flyway.configure()
                .dataSource(
                        database.url(),
                        database.username(),
                        database.password())
                .locations("classpath:db/migration")
                .target(MigrationVersion.fromVersion("47"))
                .load()
                .migrate();

        long bindingId = createBindingWithPrimary(database);

        SQLException zeroPrimary = expectSqlFailure(
                database,
                connection -> update(
                        connection,
                        """
                        UPDATE identity_binding_subject
                        SET is_primary = FALSE
                        WHERE binding_id = ?
                          AND is_primary = TRUE
                        """,
                        bindingId));
        assertConstraintViolation(zeroPrimary);

        inTransaction(database, connection -> update(
                connection,
                """
                INSERT INTO identity_binding_subject (
                    binding_id,
                    provider_code,
                    subject_type,
                    subject_value,
                    is_primary,
                    status
                ) VALUES (?, 'contract-provider', 'alias_id',
                    'contract-alias-subject', FALSE, 'ACTIVE')
                """,
                bindingId));

        inTransaction(database, connection -> {
            update(
                    connection,
                    """
                    UPDATE identity_binding_subject
                    SET is_primary = FALSE
                    WHERE binding_id = ?
                      AND is_primary = TRUE
                    """,
                    bindingId);
            update(
                    connection,
                    """
                    UPDATE identity_binding_subject
                    SET is_primary = TRUE
                    WHERE binding_id = ?
                      AND subject_type = 'alias_id'
                    """,
                    bindingId);
        });
        assertThat(activePrimaryType(database, bindingId))
                .isEqualTo("alias_id");

        SQLException twoPrimaries = expectSqlFailure(
                database,
                connection -> update(
                        connection,
                        """
                        INSERT INTO identity_binding_subject (
                            binding_id,
                            provider_code,
                            subject_type,
                            subject_value,
                            is_primary,
                            status
                        ) VALUES (?, 'contract-provider',
                            'other_primary',
                            'contract-other-primary',
                            TRUE,
                            'ACTIVE')
                        """,
                        bindingId));
        assertThat(twoPrimaries.getSQLState()).isEqualTo("23505");

        SQLException bindingWithoutPrimary = expectSqlFailure(
                database,
                connection -> {
                    try (Statement statement =
                            connection.createStatement()) {
                        insertUser(
                                statement,
                                "contract-zero-primary-user");
                        statement.executeUpdate("""
                                INSERT INTO identity_binding (
                                    user_id,
                                    provider_code,
                                    subject,
                                    login_name,
                                    created_at,
                                    updated_at
                                ) VALUES (
                                    'contract-zero-primary-user',
                                    'contract-provider',
                                    'contract-zero-primary-subject',
                                    'contract-zero-primary',
                                    CURRENT_TIMESTAMP,
                                    CURRENT_TIMESTAMP
                                )
                                """);
                    }
                });
        assertConstraintViolation(bindingWithoutPrimary);

        SQLException deletedPrimary = expectSqlFailure(
                database,
                connection -> update(
                        connection,
                        """
                        DELETE FROM identity_binding_subject
                        WHERE binding_id = ?
                          AND is_primary = TRUE
                        """,
                        bindingId));
        assertConstraintViolation(deletedPrimary);

        inTransaction(database, connection -> {
            update(
                    connection,
                    """
                    UPDATE identity_binding
                    SET status = 'REVOKED',
                        revoked_at = CURRENT_TIMESTAMP,
                        revoked_by = 'contract-test',
                        revocation_reason = 'contract test'
                    WHERE id = ?
                    """,
                    bindingId);
            update(
                    connection,
                    """
                    UPDATE identity_binding_subject
                    SET status = 'REVOKED',
                        revoked_at = CURRENT_TIMESTAMP,
                        is_primary = FALSE
                    WHERE binding_id = ?
                      AND is_primary = TRUE
                    """,
                    bindingId);
        });

        SQLException reactivatedWithoutPrimary = expectSqlFailure(
                database,
                connection -> activateBinding(
                        connection,
                        bindingId));
        assertConstraintViolation(reactivatedWithoutPrimary);

        inTransaction(database, connection -> {
            update(
                    connection,
                    """
                    UPDATE identity_binding_subject
                    SET is_primary = TRUE
                    WHERE binding_id = ?
                      AND status = 'ACTIVE'
                    """,
                    bindingId);
            activateBinding(connection, bindingId);
        });
        assertThat(activePrimaryType(database, bindingId))
                .isEqualTo("stable_id");

        inTransaction(database, connection -> update(
                connection,
                "DELETE FROM identity_binding WHERE id = ?",
                bindingId));
        try (Connection connection = database.connect();
                PreparedStatement statement = connection.prepareStatement(
                        """
                        SELECT COUNT(*)
                        FROM identity_binding_subject
                        WHERE binding_id = ?
                        """)) {
            statement.setLong(1, bindingId);
            try (ResultSet result = statement.executeQuery()) {
                assertThat(result.next()).isTrue();
                assertThat(result.getLong(1)).isZero();
            }
        }
    }

    private static long createBindingWithPrimary(Database database)
            throws Exception {
        final long[] bindingId = new long[1];
        inTransaction(database, connection -> {
            try (Statement statement = connection.createStatement()) {
                insertUser(statement, "contract-valid-user");
            }
            try (PreparedStatement statement = connection.prepareStatement(
                    """
                    INSERT INTO identity_binding (
                        user_id,
                        provider_code,
                        subject,
                        login_name,
                        created_at,
                        updated_at
                    ) VALUES (
                        'contract-valid-user',
                        'contract-provider',
                        'contract-stable-subject',
                        'contract-valid',
                        CURRENT_TIMESTAMP,
                        CURRENT_TIMESTAMP
                    )
                    RETURNING id
                    """)) {
                try (ResultSet result = statement.executeQuery()) {
                    assertThat(result.next()).isTrue();
                    bindingId[0] = result.getLong(1);
                }
            }
            update(
                    connection,
                    """
                    INSERT INTO identity_binding_subject (
                        binding_id,
                        provider_code,
                        subject_type,
                        subject_value,
                        is_primary,
                        status
                    ) VALUES (?, 'contract-provider', 'stable_id',
                        'contract-stable-subject', TRUE, 'ACTIVE')
                    """,
                    bindingId[0]);
        });
        return bindingId[0];
    }

    private static void activateBinding(
            Connection connection,
            long bindingId) throws SQLException {
        update(
                connection,
                """
                UPDATE identity_binding
                SET status = 'ACTIVE',
                    revoked_at = NULL,
                    revoked_by = NULL,
                    revocation_reason = NULL
                WHERE id = ?
                """,
                bindingId);
    }

    private static String activePrimaryType(
            Database database,
            long bindingId) throws Exception {
        try (Connection connection = database.connect();
                PreparedStatement statement = connection.prepareStatement(
                        """
                        SELECT subject_type
                        FROM identity_binding_subject
                        WHERE binding_id = ?
                          AND status = 'ACTIVE'
                          AND is_primary = TRUE
                        """)) {
            statement.setLong(1, bindingId);
            try (ResultSet result = statement.executeQuery()) {
                assertThat(result.next()).isTrue();
                String subjectType = result.getString(1);
                assertThat(result.next()).isFalse();
                return subjectType;
            }
        }
    }

    private static void assertConstraintViolation(
            SQLException failure) {
        assertThat(failure.getSQLState()).isEqualTo("23514");
        assertThat(failure.getMessage())
                .contains(
                        "must have exactly one ACTIVE primary subject");
    }

    private static SQLException expectSqlFailure(
            Database database,
            SqlWork work) throws Exception {
        try (Connection connection = database.connect()) {
            connection.setAutoCommit(false);
            try {
                work.execute(connection);
                connection.commit();
            } catch (SQLException failure) {
                connection.rollback();
                return failure;
            }
        }
        throw new AssertionError("Expected SQL transaction to fail");
    }

    private static void inTransaction(
            Database database,
            SqlWork work) throws Exception {
        try (Connection connection = database.connect()) {
            connection.setAutoCommit(false);
            try {
                work.execute(connection);
                connection.commit();
            } catch (Exception failure) {
                connection.rollback();
                throw failure;
            }
        }
    }

    private static int update(
            Connection connection,
            String sql,
            long bindingId) throws SQLException {
        try (PreparedStatement statement =
                connection.prepareStatement(sql)) {
            statement.setLong(1, bindingId);
            return statement.executeUpdate();
        }
    }

    private static void insertUser(
            Statement statement,
            String userId) throws SQLException {
        statement.executeUpdate("""
                INSERT INTO user_account (
                    id,
                    display_name,
                    status,
                    created_at,
                    updated_at
                ) VALUES (
                    '%s',
                    'Binding V2 Contract User',
                    'ACTIVE',
                    CURRENT_TIMESTAMP,
                    CURRENT_TIMESTAMP
                )
                """.formatted(userId));
    }

    private static long singleLong(
            Statement statement,
            String sql) throws SQLException {
        try (ResultSet result = statement.executeQuery(sql)) {
            assertThat(result.next()).isTrue();
            return result.getLong(1);
        }
    }

    private static String singleString(
            Statement statement,
            String sql) throws SQLException {
        try (ResultSet result = statement.executeQuery(sql)) {
            assertThat(result.next()).isTrue();
            return result.getString(1);
        }
    }

    private static void dropSchema(
            Database database,
            String schema) throws SQLException {
        if (!PREFLIGHT_SCHEMA.equals(schema)) {
            throw new IllegalArgumentException(
                    "Unexpected test schema " + schema);
        }
        try (Connection connection = database.connect();
                Statement statement = connection.createStatement()) {
            statement.execute(
                    "DROP SCHEMA IF EXISTS " + schema + " CASCADE");
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

    private static Database database() {
        return new Database(
                requiredEnvironment(
                        "IDENTITY_BINDING_V2_POSTGRES_URL"),
                requiredEnvironment(
                        "IDENTITY_BINDING_V2_POSTGRES_USERNAME"),
                requiredEnvironment(
                        "IDENTITY_BINDING_V2_POSTGRES_PASSWORD"));
    }

    private static String requiredEnvironment(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(
                    "Missing required environment variable " + name);
        }
        return value;
    }

    @FunctionalInterface
    private interface SqlWork {
        void execute(Connection connection) throws Exception;
    }

    private record Database(
            String url,
            String username,
            String password) {

        Connection connect() throws SQLException {
            return DriverManager.getConnection(
                    url,
                    username,
                    password);
        }
    }
}
