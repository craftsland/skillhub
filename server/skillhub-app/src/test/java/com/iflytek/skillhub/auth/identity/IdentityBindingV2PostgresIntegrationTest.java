package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@SpringBootTest
@ActiveProfiles("test")
@EnabledIfEnvironmentVariable(
        named = "IDENTITY_BINDING_V2_POSTGRES_URL",
        matches = "jdbc:postgresql:.*")
class IdentityBindingV2PostgresIntegrationTest {

    private static final String CONCURRENT_SUBJECT =
            "900000000003";

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
        registry.add(
                "spring.datasource.url",
                () -> requiredEnvironment(
                        "IDENTITY_BINDING_V2_POSTGRES_URL"));
        registry.add(
                "spring.datasource.username",
                () -> requiredEnvironment(
                        "IDENTITY_BINDING_V2_POSTGRES_USERNAME"));
        registry.add(
                "spring.datasource.password",
                () -> requiredEnvironment(
                        "IDENTITY_BINDING_V2_POSTGRES_PASSWORD"));
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
    }

    @Test
    void upgradesMixedVersionWriteAndPreservesLegacyReadColumn() {
        IdentityLoginOutcome outcome = authenticate(
                IdentityBindingV2MigrationPostgresTest
                        .MIXED_VERSION_SUBJECT);

        assertThat(outcome)
                .isInstanceOf(
                        IdentityLoginOutcome.Authenticated.class);
        IdentityLoginOutcome.Authenticated authenticated =
                (IdentityLoginOutcome.Authenticated) outcome;
        assertThat(authenticated.accountCreated()).isFalse();
        assertThat(authenticated.bindingCreated()).isFalse();

        Long bindingId = jdbcTemplate.queryForObject(
                """
                SELECT id
                FROM identity_binding
                WHERE user_id = ?
                  AND provider_code = 'github'
                  AND subject = ?
                  AND status = 'ACTIVE'
                """,
                Long.class,
                IdentityBindingV2MigrationPostgresTest
                        .MIXED_VERSION_USER,
                IdentityBindingV2MigrationPostgresTest
                        .MIXED_VERSION_SUBJECT);
        assertThat(bindingId).isNotNull();

        List<Map<String, Object>> subjects =
                jdbcTemplate.queryForList(
                        """
                        SELECT
                            subject_type,
                            subject_value,
                            is_primary,
                            status
                        FROM identity_binding_subject
                        WHERE binding_id = ?
                        ORDER BY subject_type
                        """,
                        bindingId);
        assertThat(subjects)
                .extracting(
                        row -> row.get("subject_type"),
                        row -> row.get("subject_value"),
                        row -> row.get("is_primary"),
                        row -> row.get("status"))
                .containsExactlyInAnyOrder(
                        org.assertj.core.groups.Tuple.tuple(
                                "github_user_id",
                                IdentityBindingV2MigrationPostgresTest
                                        .MIXED_VERSION_SUBJECT,
                                true,
                                "ACTIVE"),
                        org.assertj.core.groups.Tuple.tuple(
                                "legacy_subject",
                                IdentityBindingV2MigrationPostgresTest
                                        .MIXED_VERSION_SUBJECT,
                                false,
                                "ACTIVE"));

        assertThatThrownBy(() -> jdbcTemplate.update(
                """
                INSERT INTO identity_binding_subject (
                    binding_id,
                    provider_code,
                    subject_type,
                    subject_value,
                    is_primary,
                    status
                ) VALUES (?, 'github', 'other_primary',
                    'other-primary-value', TRUE, 'ACTIVE')
                """,
                bindingId))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void concurrentFirstLoginConvergesOnOneBinding() throws Exception {
        ResolvedProviderHandle provider = githubProvider();
        ProviderAuthenticationResult result =
                providerResult(CONCURRENT_SUBJECT);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<IdentityLoginOutcome>> futures =
                new ArrayList<>();

        try (var executor =
                Executors.newVirtualThreadPerTaskExecutor()) {
            for (int index = 0; index < 6; index++) {
                futures.add(executor.submit(() -> {
                    start.await();
                    return loginService.authenticate(
                            provider,
                            result,
                            IdentityLoginContext.empty());
                }));
            }
            start.countDown();
            List<IdentityLoginOutcome> outcomes =
                    new ArrayList<>();
            for (Future<IdentityLoginOutcome> future : futures) {
                outcomes.add(future.get());
            }
            assertThat(outcomes)
                    .allSatisfy(outcome -> assertThat(outcome)
                            .isInstanceOf(
                                    IdentityLoginOutcome
                                            .Authenticated.class));
            assertThat(outcomes.stream()
                    .map(IdentityLoginOutcome.Authenticated.class::cast)
                    .filter(IdentityLoginOutcome.Authenticated
                            ::accountCreated)
                    .count()).isEqualTo(1L);
        }

        assertThat(jdbcTemplate.queryForObject(
                """
                SELECT COUNT(*)
                FROM identity_binding
                WHERE provider_code = 'github'
                  AND subject = ?
                  AND status = 'ACTIVE'
                """,
                Long.class,
                CONCURRENT_SUBJECT)).isEqualTo(1L);
        assertThat(jdbcTemplate.queryForObject(
                """
                SELECT COUNT(*)
                FROM identity_binding_subject
                WHERE provider_code = 'github'
                  AND subject_type = 'github_user_id'
                  AND subject_value = ?
                  AND status = 'ACTIVE'
                  AND is_primary = TRUE
                """,
                Long.class,
                CONCURRENT_SUBJECT)).isEqualTo(1L);
    }

    private IdentityLoginOutcome authenticate(String subject) {
        return loginService.authenticate(
                githubProvider(),
                providerResult(subject),
                IdentityLoginContext.empty());
    }

    private ResolvedProviderHandle githubProvider() {
        ClientRegistration registration =
                registrationRepository.findByRegistrationId(
                        "github");
        assertThat(registration).isNotNull();
        return routeResolver.resolve(registration);
    }

    private static ProviderAuthenticationResult providerResult(
            String subject) {
        return new ProviderAuthenticationResult(
                new SubjectCandidate(
                        "github_user_id",
                        subject),
                List.of(),
                Map.of(
                        "login",
                        List.of(new ProviderAttributeValue(
                                "identity-v2-user",
                                ProviderAttributeTrust.ASSERTED)),
                        "email",
                        List.of(new ProviderAttributeValue(
                                subject + "@example.com",
                                ProviderAttributeTrust.VERIFIED))),
                new ProtocolAuthenticationEvidence(
                        "oauth2-github",
                        Instant.now(),
                        Set.of(
                                "oauth2_authorization_code")));
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
