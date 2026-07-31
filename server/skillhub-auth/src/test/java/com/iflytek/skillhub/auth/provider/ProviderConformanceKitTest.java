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
        ProviderConformanceKit.verifyStableSubjects(
                adapter.provider(),
                result,
                adapter.authenticate(fixture));

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
    void verifiesBrowserAndPassivePositiveFixtures() throws IOException {
        ProviderInstanceDefinition provider = providerDefinition();
        ProviderAuthenticationResult result = authenticationResult();
        PassiveAuthenticationRequest fixture =
                new PassiveAuthenticationRequest(
                        "POST",
                        "/api/v1/auth/session/bootstrap",
                        null,
                        "127.0.0.1",
                        Map.of(
                                "X-Private-Assertion",
                                List.of("fixture-assertion")));
        BrowserAuthenticationAdapter<String> browser =
                new BrowserAuthenticationAdapter<>() {
                    @Override
                    public ProviderInstanceDefinition provider() {
                        return provider;
                    }

                    @Override
                    public Class<String> exchangeType() {
                        return String.class;
                    }

                    @Override
                    public BrowserAuthenticationMethod loginMethod() {
                        return BrowserAuthenticationMethod.OAUTH_REDIRECT;
                    }

                    @Override
                    public ProviderAuthenticationResult authenticate(
                            String exchange) {
                        return result;
                    }
                };
        PassiveAuthenticationAdapter passive =
                new PassiveAuthenticationAdapter() {
                    @Override
                    public ProviderInstanceDefinition provider() {
                        return provider;
                    }

                    @Override
                    public Optional<ProviderAuthenticationResult> authenticate(
                            PassiveAuthenticationRequest request) {
                        assertThat(request).isEqualTo(fixture);
                        return Optional.of(result);
                    }
                };

        assertThat(ProviderConformanceKit.verifyBrowser(
                browser,
                "verified-exchange")).isSameAs(result);
        assertThat(ProviderConformanceKit.verifyPassive(
                passive,
                fixture))
                .isSameAs(result);
        ProviderConformanceKit.verifyAdapterBoundary(
                passive.getClass());
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
