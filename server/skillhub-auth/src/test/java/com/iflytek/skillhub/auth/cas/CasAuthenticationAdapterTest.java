package com.iflytek.skillhub.auth.cas;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.iflytek.skillhub.auth.identity.EmailAssurance;
import com.iflytek.skillhub.auth.identity.ProviderAttributeTrust;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationException;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationFailureCode;
import com.iflytek.skillhub.auth.provider.ProviderConformanceKit;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CasAuthenticationAdapterTest {

    @Test
    void mapsVerifiedPrincipalAndOnlyConfiguredProfileAttributes()
            throws IOException {
        CasProperties properties =
                CasTestConfiguration.validProperties();
        properties.getAttributes().setDisplayName("cn");
        properties.getAttributes().setEmail("mail");
        CasAuthenticationAdapter adapter =
                new CasAuthenticationAdapter(
                        CasTestConfiguration.configuration(properties));
        CasAuthenticationExchange exchange =
                new CasAuthenticationExchange(
                        "alice-123",
                        Map.of(
                                "cn",
                                List.of("Alice"),
                                "mail",
                                List.of("alice@example.com"),
                                "unmapped",
                                List.of("must-not-leak")),
                        Instant.parse("2026-07-31T00:00:00Z"));

        var result = ProviderConformanceKit.verifyBrowser(
                adapter,
                exchange);

        assertThat(result.primarySubject().type())
                .isEqualTo("cas_principal");
        assertThat(result.primarySubject().value())
                .isEqualTo("alice-123");
        assertThat(result.attributes())
                .containsOnlyKeys(
                        CasAuthenticationAdapter
                                .DISPLAY_NAME_ATTRIBUTE,
                        CasAuthenticationAdapter.EMAIL_ATTRIBUTE);
        assertThat(result.attributes()
                .get(CasAuthenticationAdapter.EMAIL_ATTRIBUTE)
                .getFirst()
                .trust()).isEqualTo(
                        ProviderAttributeTrust.ASSERTED);
        assertThat(adapter.provider().emailAssuranceLimit())
                .isEqualTo(EmailAssurance.PROVIDER_ASSERTED);
        ProviderConformanceKit.verifyAdapterBoundary(
                CasAuthenticationAdapter.class);
    }

    @Test
    void explicitlyConfiguredImmutableAttributeBecomesSubject() {
        CasProperties properties =
                CasTestConfiguration.validProperties();
        properties.setSubjectType("cas_employee_id");
        properties.getAttributes().setSubject("employeeId");
        CasAuthenticationAdapter adapter =
                new CasAuthenticationAdapter(
                        CasTestConfiguration.configuration(properties));

        var result = adapter.authenticate(
                new CasAuthenticationExchange(
                        "mutable-login",
                        Map.of(
                                "employeeId",
                                List.of("employee-42")),
                        Instant.parse("2026-07-31T00:00:00Z")));

        assertThat(result.primarySubject().type())
                .isEqualTo("cas_employee_id");
        assertThat(result.primarySubject().value())
                .isEqualTo("employee-42");
    }

    @Test
    void missingOrAmbiguousConfiguredSubjectFailsClosed() {
        CasProperties properties =
                CasTestConfiguration.validProperties();
        properties.setSubjectType("cas_employee_id");
        properties.getAttributes().setSubject("employeeId");
        CasAuthenticationAdapter adapter =
                new CasAuthenticationAdapter(
                        CasTestConfiguration.configuration(properties));

        assertThatThrownBy(() -> adapter.authenticate(
                new CasAuthenticationExchange(
                        "alice",
                        Map.of(),
                        Instant.parse("2026-07-31T00:00:00Z"))))
                .isInstanceOf(ProviderAuthenticationException.class)
                .extracting("reasonCode")
                .isEqualTo(ProviderAuthenticationFailureCode
                        .UPSTREAM_INVALID_RESPONSE);

        assertThatThrownBy(() -> adapter.authenticate(
                new CasAuthenticationExchange(
                        "alice",
                        Map.of(
                                "employeeId",
                                List.of("one", "two")),
                        Instant.parse("2026-07-31T00:00:00Z"))))
                .isInstanceOf(ProviderAuthenticationException.class)
                .extracting("reasonCode")
                .isEqualTo(ProviderAuthenticationFailureCode
                        .UPSTREAM_INVALID_RESPONSE);

        assertThatThrownBy(() -> adapter.authenticate(
                new CasAuthenticationExchange(
                        "alice",
                        Map.of(
                                "employeeId",
                                List.of("x".repeat(4097))),
                        Instant.parse("2026-07-31T00:00:00Z"))))
                .isInstanceOf(ProviderAuthenticationException.class)
                .extracting("reasonCode")
                .isEqualTo(ProviderAuthenticationFailureCode
                        .UPSTREAM_INVALID_RESPONSE);
    }

    @Test
    void disabledAdapterHasNoRoutableDefinition() {
        CasProperties properties = new CasProperties();
        CasAuthenticationAdapter adapter =
                new CasAuthenticationAdapter(
                        CasTestConfiguration.configuration(properties));

        assertThat(adapter.provider().enabled()).isFalse();
    }
}
