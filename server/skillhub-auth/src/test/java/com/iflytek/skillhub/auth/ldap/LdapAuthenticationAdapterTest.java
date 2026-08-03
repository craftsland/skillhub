package com.iflytek.skillhub.auth.ldap;

import static org.assertj.core.api.Assertions.assertThat;

import com.iflytek.skillhub.auth.identity.EmailAssurance;
import com.iflytek.skillhub.auth.identity.ProviderAttributeTrust;
import com.iflytek.skillhub.auth.provider.CredentialAuthenticationRequest;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationException;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationFailureCode;
import com.iflytek.skillhub.auth.provider.ProviderConformanceKit;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

class LdapAuthenticationAdapterTest {

    @Test
    void mapsAuthenticatedEntryIntoUnifiedProviderFacts()
            throws IOException {
        LdapProperties properties = validProperties();
        LdapProviderConfiguration configuration =
                new LdapProviderConfiguration(
                        properties,
                        new MockEnvironment().withProperty(
                                "spring.profiles.active",
                                "prod"));
        LdapDirectoryClient directoryClient = (provider, request) -> {
            assertThat(request.username()).isEqualTo("alice");
            assertThat(request.password()).isEqualTo("fixture-password");
            return new LdapAuthenticatedEntry(
                    "550e8400-e29b-41d4-a716-446655440000",
                    Map.of(
                            "uid", List.of("alice"),
                            "displayName", List.of("Alice Directory"),
                            "mail", List.of("alice@example.com"),
                            "unmapped", List.of("must-not-leak")),
                    Instant.parse("2026-07-31T10:00:00Z"));
        };
        LdapAuthenticationAdapter adapter =
                new LdapAuthenticationAdapter(
                        configuration,
                        directoryClient);

        var result = ProviderConformanceKit.verifyCredential(
                adapter,
                new CredentialAuthenticationRequest(
                        "alice",
                        "fixture-password"));

        assertThat(result.primarySubject().type())
                .isEqualTo("ldap_entry_uuid");
        assertThat(result.primarySubject().value())
                .isEqualTo("550e8400-e29b-41d4-a716-446655440000");
        assertThat(result.attributes()).containsOnlyKeys(
                LdapAuthenticationAdapter.USERNAME_ATTRIBUTE,
                LdapAuthenticationAdapter.DISPLAY_NAME_ATTRIBUTE,
                LdapAuthenticationAdapter.EMAIL_ATTRIBUTE);
        assertThat(result.attributes()
                .get(LdapAuthenticationAdapter.EMAIL_ATTRIBUTE)
                .getFirst()
                .trust()).isEqualTo(ProviderAttributeTrust.ASSERTED);
        assertThat(adapter.provider().emailAssuranceLimit())
                .isEqualTo(EmailAssurance.PROVIDER_ASSERTED);
        assertThat(adapter.provider().authoritativeEmailSource())
                .isFalse();
        ProviderConformanceKit.verifyAdapterBoundary(
                LdapAuthenticationAdapter.class);
    }

    @Test
    void keepsAuthoritativeDirectoryEmailAsAssertedProviderFact()
            throws IOException {
        LdapProperties properties = validProperties();
        properties.setEmailAuthoritative(true);
        LdapAuthenticationAdapter adapter =
                new LdapAuthenticationAdapter(
                        new LdapProviderConfiguration(
                                properties,
                                new MockEnvironment().withProperty(
                                        "spring.profiles.active",
                                        "prod")),
                        (provider, request) ->
                                new LdapAuthenticatedEntry(
                                        "550e8400-e29b-41d4-a716-446655440000",
                                        Map.of(
                                                "mail",
                                                List.of(
                                                        "alice@example.com")),
                                        Instant.parse(
                                                "2026-07-31T10:00:00Z")));

        var result = ProviderConformanceKit.verifyCredential(
                adapter,
                new CredentialAuthenticationRequest(
                        "alice",
                        "fixture-password"));

        assertThat(result.attributes()
                .get(LdapAuthenticationAdapter.EMAIL_ATTRIBUTE)
                .getFirst()
                .trust()).isEqualTo(ProviderAttributeTrust.ASSERTED);
        assertThat(adapter.provider().emailAssuranceLimit())
                .isEqualTo(EmailAssurance.AUTHORITATIVE);
        assertThat(adapter.provider().authoritativeEmailSource())
                .isTrue();
    }

    @Test
    void recordsOnlyBoundedProtocolOutcomeLabels() {
        LdapProperties properties = validProperties();
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        LdapAuthenticationAdapter adapter =
                new LdapAuthenticationAdapter(
                        new LdapProviderConfiguration(
                                properties,
                                new MockEnvironment().withProperty(
                                        "spring.profiles.active",
                                        "prod")),
                        (provider, request) -> {
                            throw new ProviderAuthenticationException(
                                    ProviderAuthenticationFailureCode
                                            .UPSTREAM_INVALID_CREDENTIALS);
                        },
                        new LdapAuthenticationMetrics(registry));

        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
                adapter.authenticate(
                        new CredentialAuthenticationRequest(
                                "alice",
                                "fixture-password")))
                .isInstanceOf(ProviderAuthenticationException.class);

        assertThat(registry.get("skillhub.auth.ldap")
                .tags(
                        "provider",
                        "corporate-ldap",
                        "transport",
                        "ldaps",
                        "result",
                        "upstream_invalid_credentials")
                .counter()
                .count()).isEqualTo(1.0);
    }

    private static LdapProperties validProperties() {
        LdapProperties properties = new LdapProperties();
        properties.setEnabled(true);
        properties.setProviderCode("corporate-ldap");
        properties.setDisplayName("Corporate Directory");
        properties.setAuthority("corp-directory-v1");
        properties.setUrl("ldaps://ldap.example.com:636");
        properties.setBaseDn("dc=example,dc=com");
        properties.setBindDn("cn=reader,dc=example,dc=com");
        properties.setBindPassword("fixture-password");
        return properties;
    }
}
