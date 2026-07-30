package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.iflytek.skillhub.service.AdminUserAppService;
import com.iflytek.skillhub.service.AuditRequestContext;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
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
class IdentityProfileProvisioningPostgresIntegrationTest {

    private static final String SCHEMA =
            "identity_profile_p3_integration";
    private static final Set<String> PROVIDERS = Set.of(
            "profile-auto",
            "profile-approval",
            "profile-existing-only",
            "profile-collision",
            "profile-preserve");

    @Autowired
    private IdentityResolutionTransaction transaction;

    @Autowired
    private AdminUserAppService adminUserAppService;

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
    }

    @BeforeEach
    void seedProviderStates() {
        jdbcTemplate.update(
                """
                INSERT INTO user_account (
                    id,
                    display_name,
                    status,
                    created_at,
                    updated_at
                ) VALUES (
                    'profile-test-admin',
                    'Profile Test Admin',
                    'ACTIVE',
                    CURRENT_TIMESTAMP,
                    CURRENT_TIMESTAMP
                )
                ON CONFLICT (id) DO NOTHING
                """);
        for (String provider : PROVIDERS) {
            jdbcTemplate.update(
                    """
                    INSERT INTO identity_provider_state (
                        provider_code,
                        protocol,
                        authority,
                        authority_fingerprint,
                        state
                    ) VALUES (?, 'oidc', ?, ?, 'READY')
                    ON CONFLICT (provider_code) DO NOTHING
                    """,
                    provider,
                    "https://" + provider + ".example.com",
                    "a".repeat(64));
        }
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
                    "Failed to remove identity profile test schema",
                    exception);
        }
    }

    @Test
    void approvalIsIdempotentAndAdminApprovalAddsMembership() {
        String provider = "profile-approval";
        String subject = "approval-user";
        ProviderDescriptor descriptor = descriptor(
                provider,
                ProvisioningMode.APPROVAL,
                ProfileSyncPolicy.defaults());
        IdentityAssertion assertion = assertion(
                provider,
                subject,
                "Approval User",
                "approval@example.com",
                EmailAssurance.VERIFIED);

        IdentityLoginOutcome first = transaction.resolve(
                assertion,
                descriptor,
                IdentityLoginContext.empty());
        IdentityLoginOutcome repeated = transaction.resolve(
                assertion,
                descriptor,
                IdentityLoginContext.empty());

        assertThat(first).isEqualTo(
                new IdentityLoginOutcome.PendingApproval(
                        "ACCOUNT_PENDING"));
        assertThat(repeated).isEqualTo(first);
        String userId = userId(provider, subject);
        assertThat(count(
                "SELECT COUNT(*) FROM user_account WHERE id = ? AND status = 'PENDING'",
                userId)).isEqualTo(1L);
        assertThat(count(
                "SELECT COUNT(*) FROM identity_binding WHERE user_id = ?",
                userId)).isEqualTo(1L);
        assertThat(count(
                "SELECT COUNT(*) FROM user_profile_field_source WHERE user_id = ?",
                userId)).isEqualTo(3L);
        assertThat(count(
                "SELECT COUNT(*) FROM namespace_member WHERE user_id = ?",
                userId)).isZero();

        adminUserAppService.updateUserStatus(
                userId,
                "ACTIVE",
                "profile-test-admin",
                new AuditRequestContext(
                        "127.0.0.1",
                        "identity-profile-test"));

        assertThat(count(
                """
                SELECT COUNT(*)
                FROM namespace_member member
                JOIN namespace namespace
                  ON namespace.id = member.namespace_id
                WHERE member.user_id = ?
                  AND namespace.slug = 'global'
                  AND member.role = 'MEMBER'
                """,
                userId)).isEqualTo(1L);
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM audit_log
                WHERE actor_user_id = 'profile-test-admin'
                  AND action =
                      'IDENTITY_PROVISIONING_APPROVED'
                  AND detail_json ->> 'userId' = ?
                """,
                userId)).isEqualTo(1L);
        assertThat(transaction.resolve(
                assertion,
                descriptor,
                IdentityLoginContext.empty()))
                .isInstanceOf(
                        IdentityLoginOutcome.Authenticated.class);
    }

    @Test
    void rejectedPendingAccountKeepsBindingAndCannotReprovision() {
        String provider = "profile-approval";
        String subject = "rejected-user";
        ProviderDescriptor descriptor = descriptor(
                provider,
                ProvisioningMode.APPROVAL,
                ProfileSyncPolicy.defaults());
        IdentityAssertion assertion = assertion(
                provider,
                subject,
                "Rejected User",
                "rejected@example.com",
                EmailAssurance.VERIFIED);
        transaction.resolve(
                assertion,
                descriptor,
                IdentityLoginContext.empty());
        String userId = userId(provider, subject);

        adminUserAppService.updateUserStatus(
                userId,
                "DISABLED",
                "profile-test-admin",
                new AuditRequestContext(
                        "127.0.0.1",
                        "identity-profile-test"));

        assertThatThrownBy(() -> transaction.resolve(
                assertion,
                descriptor,
                IdentityLoginContext.empty()))
                .isInstanceOf(IdentityCoreException.class)
                .extracting("reasonCode")
                .isEqualTo(
                        IdentityFailureCode.ACCOUNT_DISABLED);
        assertThat(count(
                "SELECT COUNT(*) FROM identity_binding WHERE user_id = ? AND status = 'ACTIVE'",
                userId)).isEqualTo(1L);
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM audit_log
                WHERE actor_user_id = 'profile-test-admin'
                  AND action =
                      'IDENTITY_PROVISIONING_REJECTED'
                  AND detail_json ->> 'userId' = ?
                """,
                userId)).isEqualTo(1L);
    }

    @Test
    void existingBindingOnlyLeavesNoAccountOrBinding() {
        String provider = "profile-existing-only";
        String subject = "unknown-user";

        assertThatThrownBy(() -> transaction.resolve(
                assertion(
                        provider,
                        subject,
                        "Unknown User",
                        "unknown@example.com",
                        EmailAssurance.VERIFIED),
                descriptor(
                        provider,
                        ProvisioningMode.EXISTING_BINDING_ONLY,
                        ProfileSyncPolicy.defaults()),
                IdentityLoginContext.empty()))
                .isInstanceOf(IdentityCoreException.class)
                .extracting("reasonCode")
                .isEqualTo(IdentityFailureCode.ACCESS_DENIED);
        assertThat(count(
                "SELECT COUNT(*) FROM identity_binding WHERE provider_code = ?",
                provider)).isZero();
        assertThat(count(
                "SELECT COUNT(*) FROM user_account WHERE email = ?",
                "unknown@example.com")).isZero();
    }

    @Test
    void verifiedEmailCollisionReturnsSafeOutcomeWithoutWriting() {
        String provider = "profile-collision";
        jdbcTemplate.update(
                """
                INSERT INTO user_account (
                    id,
                    display_name,
                    email,
                    status,
                    created_at,
                    updated_at
                ) VALUES (
                    'existing-collision-user',
                    'Existing User',
                    'collision@example.com',
                    'ACTIVE',
                    CURRENT_TIMESTAMP,
                    CURRENT_TIMESTAMP
                )
                """);

        IdentityLoginOutcome outcome = transaction.resolve(
                assertion(
                        provider,
                        "collision-subject",
                        "Collision User",
                        "collision@example.com",
                        EmailAssurance.VERIFIED),
                descriptor(
                        provider,
                        ProvisioningMode.AUTO,
                        ProfileSyncPolicy.defaults()),
                IdentityLoginContext.empty());

        assertThat(outcome).isEqualTo(
                new IdentityLoginOutcome.LinkRequired(
                        "EMAIL_COLLISION"));
        assertThat(count(
                "SELECT COUNT(*) FROM identity_binding WHERE provider_code = ?",
                provider)).isZero();
        assertThat(count(
                "SELECT COUNT(*) FROM user_account WHERE email = ?",
                "collision@example.com")).isEqualTo(1L);
    }

    @Test
    void returningLoginPreservesLocallyMaintainedDisplayName() {
        String provider = "profile-preserve";
        String subject = "preserve-user";
        ProviderDescriptor descriptor = descriptor(
                provider,
                ProvisioningMode.AUTO,
                ProfileSyncPolicy.defaults());
        transaction.resolve(
                assertion(
                        provider,
                        subject,
                        "Provider Name",
                        "preserve@example.com",
                        EmailAssurance.VERIFIED),
                descriptor,
                IdentityLoginContext.empty());
        String userId = userId(provider, subject);
        jdbcTemplate.update(
                """
                UPDATE user_account
                SET display_name = 'Local Name'
                WHERE id = ?
                """,
                userId);
        jdbcTemplate.update(
                """
                UPDATE user_profile_field_source
                SET
                    source_type = 'USER',
                    provider_code = NULL,
                    assurance = NULL,
                    last_synchronized_at = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE user_id = ?
                  AND field_name = 'displayName'
                """,
                userId);

        transaction.resolve(
                assertion(
                        provider,
                        subject,
                        "Changed Provider Name",
                        "preserve@example.com",
                        EmailAssurance.VERIFIED),
                descriptor,
                IdentityLoginContext.empty());

        assertThat(jdbcTemplate.queryForObject(
                """
                SELECT display_name
                FROM user_account
                WHERE id = ?
                """,
                String.class,
                userId)).isEqualTo("Local Name");
        assertThat(jdbcTemplate.queryForObject(
                """
                SELECT source_type
                FROM user_profile_field_source
                WHERE user_id = ?
                  AND field_name = 'displayName'
                """,
                String.class,
                userId)).isEqualTo("USER");
    }

    @Test
    void returningLoginBackfillsRowsCreatedDuringRollbackWindow() {
        String provider = "profile-preserve";
        String subject = "rollback-window-user";
        jdbcTemplate.update(
                """
                INSERT INTO user_account (
                    id,
                    display_name,
                    email,
                    status,
                    created_at,
                    updated_at
                ) VALUES (
                    'rollback-window-account',
                    'Rollback Window Name',
                    'rollback-window@example.com',
                    'ACTIVE',
                    CURRENT_TIMESTAMP,
                    CURRENT_TIMESTAMP
                )
                """);
        jdbcTemplate.update(
                """
                WITH created_binding AS (
                    INSERT INTO identity_binding (
                        user_id,
                        provider_code,
                        subject,
                        login_name,
                        status,
                        created_at,
                        updated_at
                    ) VALUES (
                        'rollback-window-account',
                        ?,
                        ?,
                        'rollback-window',
                        'ACTIVE',
                        CURRENT_TIMESTAMP,
                        CURRENT_TIMESTAMP
                    )
                    RETURNING id, provider_code
                )
                INSERT INTO identity_binding_subject (
                    binding_id,
                    provider_code,
                    subject_type,
                    subject_value,
                    is_primary,
                    status,
                    created_at
                )
                SELECT
                    id,
                    provider_code,
                    'oidc_sub',
                    ?,
                    TRUE,
                    'ACTIVE',
                    CURRENT_TIMESTAMP
                FROM created_binding
                """,
                provider,
                subject,
                subject);

        transaction.resolve(
                assertion(
                        provider,
                        subject,
                        "New Provider Name",
                        "new-provider@example.com",
                        EmailAssurance.VERIFIED),
                descriptor(
                        provider,
                        ProvisioningMode.AUTO,
                        ProfileSyncPolicy.defaults()),
                IdentityLoginContext.empty());

        assertThat(jdbcTemplate.queryForObject(
                """
                SELECT display_name
                FROM user_account
                WHERE id = 'rollback-window-account'
                """,
                String.class)).isEqualTo(
                        "Rollback Window Name");
        assertThat(count(
                """
                SELECT COUNT(*)
                FROM user_profile_field_source
                WHERE user_id = 'rollback-window-account'
                  AND source_type = 'LEGACY_LOCAL'
                """)).isEqualTo(2L);
    }

    @Test
    void profileSourceFailureRollsBackAccountAndBinding() {
        String provider = "profile-missing-provider";
        String subject = "rollback-user";

        assertThatThrownBy(() -> transaction.resolve(
                assertion(
                        provider,
                        subject,
                        "Rollback User",
                        "rollback@example.com",
                        EmailAssurance.VERIFIED),
                descriptor(
                        provider,
                        ProvisioningMode.AUTO,
                        ProfileSyncPolicy.defaults()),
                IdentityLoginContext.empty()))
                .isInstanceOf(RuntimeException.class);

        assertThat(count(
                "SELECT COUNT(*) FROM identity_binding WHERE provider_code = ?",
                provider)).isZero();
        assertThat(count(
                "SELECT COUNT(*) FROM user_account WHERE email = ?",
                "rollback@example.com")).isZero();
        assertThat(count(
                "SELECT COUNT(*) FROM user_profile_field_source WHERE provider_code = ?",
                provider)).isZero();
    }

    private String userId(
            String provider,
            String subject) {
        return jdbcTemplate.queryForObject(
                """
                SELECT user_id
                FROM identity_binding
                WHERE provider_code = ?
                  AND subject = ?
                """,
                String.class,
                provider,
                subject);
    }

    private long count(String sql, Object... arguments) {
        Long result = jdbcTemplate.queryForObject(
                sql,
                Long.class,
                arguments);
        return result == null ? 0L : result;
    }

    private static ProviderDescriptor descriptor(
            String provider,
            ProvisioningMode provisioningMode,
            ProfileSyncPolicy profileSyncPolicy) {
        return new ProviderDescriptor(
                provider,
                "oidc",
                "https://" + provider + ".example.com",
                provider,
                "oidc_sub",
                "oidc_sub",
                Map.of(
                        "oidc_sub",
                        SubjectCanonicalizer.EXACT),
                List.of("name"),
                List.of("email"),
                List.of(),
                EmailAssurance.VERIFIED,
                provisioningMode,
                profileSyncPolicy);
    }

    private static IdentityAssertion assertion(
            String provider,
            String subject,
            String displayName,
            String email,
            EmailAssurance assurance) {
        return new IdentityAssertion(
                new ProviderReference(
                        provider,
                        "oidc",
                        "https://" + provider + ".example.com"),
                new ExternalSubject("oidc_sub", subject),
                Set.of(),
                new ExternalProfile(
                        displayName,
                        Optional.of(new EmailClaim(
                                email,
                                assurance)),
                        Optional.empty()),
                Map.of(),
                new AuthenticationEvidence(
                        "oidc",
                        Instant.now(),
                        Set.of("oidc_authorization_code")));
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
                    "CREATE SCHEMA IF NOT EXISTS " + SCHEMA);
        } catch (Exception exception) {
            throw new IllegalStateException(
                    "Failed to create identity profile test schema",
                    exception);
        }
    }

    private static String withCurrentSchema(String url) {
        return url
                + (url.contains("?") ? "&" : "?")
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
