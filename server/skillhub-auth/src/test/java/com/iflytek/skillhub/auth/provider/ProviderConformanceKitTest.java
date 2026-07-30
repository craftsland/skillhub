package com.iflytek.skillhub.auth.provider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.iflytek.skillhub.auth.identity.EmailAssurance;
import com.iflytek.skillhub.auth.identity.ProtocolAuthenticationEvidence;
import com.iflytek.skillhub.auth.identity.ProviderAttributeTrust;
import com.iflytek.skillhub.auth.identity.ProviderAttributeValue;
import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;
import com.iflytek.skillhub.auth.identity.SubjectCandidate;
import com.iflytek.skillhub.auth.oauth.GitHubClaimsExtractor;
import com.iflytek.skillhub.auth.oauth.GitLabClaimsExtractor;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class ProviderConformanceKitTest {

    @Test
    void verifiesDeterministicDefinitionAndProtocolFacts() {
        AtomicReference<CredentialAuthenticationRequest> observed =
                new AtomicReference<>();
        CredentialAuthenticationAdapter adapter =
                new CredentialAuthenticationAdapter() {
                    @Override
                    public ProviderInstanceDefinition provider() {
                        return providerDefinition();
                    }

                    @Override
                    public ProviderAuthenticationResult authenticate(
                            CredentialAuthenticationRequest request) {
                        observed.set(request);
                        return authenticationResult();
                    }
                };
        CredentialAuthenticationRequest fixture =
                new CredentialAuthenticationRequest(
                        "alice",
                        "fixture-password");

        ProviderAuthenticationResult result =
                ProviderConformanceKit.verifyCredential(
                        adapter,
                        fixture);

        assertThat(result.primarySubject().value())
                .isEqualTo("entry-123");
        assertThat(observed.get()).isEqualTo(fixture);
    }

    @Test
    void providerAdaptersCannotReachAccountsRolesSessionsOrPersistence()
            throws IOException {
        ProviderConformanceKit.verifyAdapterBoundary(
                BrowserAuthenticationAdapter.class,
                CredentialAuthenticationAdapter.class,
                PassiveAuthenticationAdapter.class,
                GitHubClaimsExtractor.class,
                GitLabClaimsExtractor.class);
    }

    @Test
    void verifiesBrowserAndPassivePositiveFixtures() {
        ProviderInstanceDefinition provider = providerDefinition();
        ProviderAuthenticationResult result = authenticationResult();
        BrowserAuthenticationAdapter<String> browser =
                exchange -> result;
        PassiveAuthenticationAdapter passive =
                new PassiveAuthenticationAdapter() {
                    @Override
                    public ProviderInstanceDefinition provider() {
                        return provider;
                    }

                    @Override
                    public Optional<ProviderAuthenticationResult> authenticate(
                            HttpServletRequest request) {
                        return Optional.of(result);
                    }
                };

        assertThat(ProviderConformanceKit.verifyBrowser(
                provider,
                browser,
                "verified-exchange")).isSameAs(result);
        assertThat(ProviderConformanceKit.verifyPassive(
                passive,
                org.mockito.Mockito.mock(HttpServletRequest.class)))
                .isSameAs(result);
    }

    @Test
    void rejectsEmailTrustAboveProviderLimit() {
        ProviderInstanceDefinition provider =
                providerDefinition(EmailAssurance.UNVERIFIED);

        assertThatThrownBy(() -> ProviderConformanceKit.verifyResult(
                provider,
                authenticationResult()))
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("email assurance");
    }

    private static ProviderInstanceDefinition providerDefinition() {
        return providerDefinition(EmailAssurance.VERIFIED);
    }

    private static ProviderInstanceDefinition providerDefinition(
            EmailAssurance emailAssuranceLimit) {
        return new ProviderInstanceDefinition(
                "directory",
                "ldap",
                "ldaps://directory.example",
                "Corporate Directory",
                "ldap_entry_uuid",
                "ldap_entry_uuid",
                Map.of(
                        "ldap_entry_uuid",
                        SubjectNormalization.EXACT),
                List.of("displayName"),
                List.of("mail"),
                List.of("jpegPhoto"),
                emailAssuranceLimit);
    }

    private static ProviderAuthenticationResult authenticationResult() {
        return new ProviderAuthenticationResult(
                new SubjectCandidate(
                        "ldap_entry_uuid",
                        "entry-123"),
                List.of(),
                Map.of(
                        "displayName",
                        List.of(new ProviderAttributeValue(
                                "Alice",
                                ProviderAttributeTrust.ASSERTED)),
                        "mail",
                        List.of(new ProviderAttributeValue(
                                "alice@example.com",
                                ProviderAttributeTrust.VERIFIED))),
                new ProtocolAuthenticationEvidence(
                        "ldap",
                        Instant.parse("2026-07-30T00:00:00Z"),
                        Set.of("password")));
    }
}
