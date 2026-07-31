package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@SpringBootTest
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@EnabledIfEnvironmentVariable(
        named = "IDENTITY_BINDING_V2_POSTGRES_URL",
        matches = "jdbc:postgresql:.*")
class IdentityLinkMigrationLoginPostgresIntegrationTest {

    private static final String SCHEMA =
            "identity_link_v49_login";
    private static final String USER_ID =
            "identity-link-v49-login-user";
    private static final String SUBJECT =
            "6554902";

    @Autowired
    private ExternalIdentityLoginService loginService;

    @Autowired
    private TrustedProviderRouteResolver routeResolver;

    @Autowired
    private ClientRegistrationRepository registrationRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @DynamicPropertySource
    static void postgresProperties(
            DynamicPropertyRegistry registry) {
        String url = requiredEnvironment(
                "IDENTITY_BINDING_V2_POSTGRES_URL");
        String username = requiredEnvironment(
                "IDENTITY_BINDING_V2_POSTGRES_USERNAME");
        String password = requiredEnvironment(
                "IDENTITY_BINDING_V2_POSTGRES_PASSWORD");
        prepareV48DatabaseAndUpgrade(
                url,
                username,
                password);
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
                () -> "false");
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
                    "Failed to remove V49 login test schema",
                    exception);
        }
    }

    @Test
    void activeV48BindingStillAuthenticatesThroughUnifiedLogin()
            throws Exception {
        ClientRegistration registration =
                registrationRepository.findByRegistrationId(
                        "github");
        assertThat(registration).isNotNull();
        ResolvedProviderHandle provider =
                routeResolver.resolve(registration);

        IdentityLoginOutcome outcome = loginService.authenticate(
                provider,
                providerResult(),
                IdentityLoginContext.empty());

        assertThat(outcome)
                .isInstanceOf(
                        IdentityLoginOutcome.Authenticated.class);
        IdentityLoginOutcome.Authenticated authenticated =
                (IdentityLoginOutcome.Authenticated) outcome;
        assertThat(authenticated.principal().userId())
                .isEqualTo(USER_ID);
        assertThat(authenticated.accountCreated()).isFalse();
        assertThat(authenticated.bindingCreated()).isFalse();
        assertThat(jdbcTemplate.queryForObject(
                """
                SELECT COUNT(*)
                FROM identity_binding
                WHERE user_id = ?
                  AND provider_code = 'github'
                  AND subject = ?
                  AND status = 'ACTIVE'
                """,
                Long.class,
                USER_ID,
                SUBJECT)).isEqualTo(1L);
        assertThat(jdbcTemplate.queryForObject(
                """
                SELECT COUNT(*)
                FROM identity_link_request
                """,
                Long.class)).isZero();
    }

    private static void prepareV48DatabaseAndUpgrade(
            String url,
            String username,
            String password) {
        dropAndCreateSchema(url, username, password);
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
            connection.setAutoCommit(false);
            statement.executeUpdate("""
                    INSERT INTO user_account (
                        id,
                        display_name,
                        email,
                        status,
                        created_at,
                        updated_at
                    ) VALUES (
                        'identity-link-v49-login-user',
                        'Identity Link V49 Login User',
                        'identity-link-v49-login@example.com',
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
                        status,
                        created_at,
                        updated_at
                    ) VALUES (
                        'identity-link-v49-login-user',
                        'github',
                        '6554902',
                        'identity-link-v49-login',
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
                    WHERE user_id =
                        'identity-link-v49-login-user'
                    """);
            connection.commit();
        } catch (Exception exception) {
            throw new IllegalStateException(
                    "Failed to seed V48 login fixture",
                    exception);
        }
        Flyway.configure()
                .dataSource(url, username, password)
                .locations("classpath:db/migration")
                .schemas(SCHEMA)
                .defaultSchema(SCHEMA)
                .createSchemas(true)
                .load()
                .migrate();
    }

    private static ProviderAuthenticationResult providerResult() {
        return new ProviderAuthenticationResult(
                new SubjectCandidate(
                        "github_user_id",
                        SUBJECT),
                List.of(),
                Map.of(
                        "login",
                        List.of(new ProviderAttributeValue(
                                "identity-link-v49-login",
                                ProviderAttributeTrust.ASSERTED)),
                        "email",
                        List.of(new ProviderAttributeValue(
                                "identity-link-v49-login@example.com",
                                ProviderAttributeTrust.VERIFIED))),
                new ProtocolAuthenticationEvidence(
                        "oauth2-github",
                        Instant.now(),
                        Set.of("oauth2_authorization_code")));
    }

    private static void dropAndCreateSchema(
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
                    "Failed to prepare V49 login test schema",
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
                    "Missing required environment variable "
                            + name);
        }
        return value;
    }
}
