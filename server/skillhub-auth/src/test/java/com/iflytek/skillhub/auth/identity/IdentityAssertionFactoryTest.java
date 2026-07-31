package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class IdentityAssertionFactoryTest {

    private static final Instant AUTHENTICATED_AT = Instant.parse("2026-07-30T08:00:00Z");

    private final IdentityAssertionFactory factory = new IdentityAssertionFactory();

    @Test
    void createsAssertionFromTrustedDescriptorAndVerifiedProviderFacts() {
        ProviderAuthenticationResult result = result(
                new SubjectCandidate("github_user_id", "123456"),
                List.of(),
                Map.of(
                        "login", values("alice", ProviderAttributeTrust.ASSERTED),
                        "email", values("alice@example.com", ProviderAttributeTrust.VERIFIED),
                        "avatar_url", values("https://avatars.example/alice.png", ProviderAttributeTrust.ASSERTED),
                        "ignored_role", values("SUPER_ADMIN", ProviderAttributeTrust.VERIFIED)
                ),
                "oauth2-github"
        );

        IdentityAssertion assertion = factory.create(githubDescriptor(), result);

        assertThat(assertion.provider()).isEqualTo(
                new ProviderReference("github", "oauth2-github", "https://github.com"));
        assertThat(assertion.primarySubject()).isEqualTo(
                new ExternalSubject("github_user_id", "123456"));
        assertThat(assertion.alternateSubjects()).isEmpty();
        assertThat(assertion.profile().displayName()).isEqualTo("alice");
        assertThat(assertion.profile().email()).contains(
                new EmailClaim("alice@example.com", EmailAssurance.VERIFIED));
        assertThat(assertion.profile().avatarUrl())
                .hasValueSatisfying(uri -> assertThat(uri.toString())
                        .isEqualTo("https://avatars.example/alice.png"));
        assertThat(assertion.mappedAttributes()).isEmpty();
        assertThat(assertion.evidence()).isEqualTo(
                new AuthenticationEvidence(
                        "oauth2-github",
                        AUTHENTICATED_AT,
                        Set.of("oauth2_authorization_code")));
    }

    @Test
    void clampsEmailTrustToDescriptorAssuranceLimit() {
        ProviderDescriptor descriptor = new ProviderDescriptor(
                "corp-oidc",
                "oidc",
                "https://id.example.com",
                "Corporate OIDC",
                "oidc_sub",
                "oidc_sub",
                Map.of("oidc_sub", SubjectCanonicalizer.EXACT),
                List.of("preferred_username", "name", "sub"),
                List.of("email"),
                List.of("picture"),
                EmailAssurance.PROVIDER_ASSERTED
        );
        ProviderAuthenticationResult result = result(
                new SubjectCandidate("oidc_sub", "CaseSensitiveSubject"),
                List.of(),
                Map.of(
                        "preferred_username", values("alice", ProviderAttributeTrust.ASSERTED),
                        "email", values("alice@example.com", ProviderAttributeTrust.VERIFIED)
                ),
                "oidc"
        );

        IdentityAssertion assertion = factory.create(descriptor, result);

        assertThat(assertion.profile().email()).contains(
                new EmailClaim("alice@example.com", EmailAssurance.PROVIDER_ASSERTED));
        assertThat(assertion.primarySubject().value()).isEqualTo("CaseSensitiveSubject");
    }

    @Test
    void promotesAssertedEmailOnlyForTrustedAuthoritativeSource() {
        ProviderDescriptor descriptor = new ProviderDescriptor(
                "corporate-ldap",
                "ldap",
                "corp-directory-v1",
                "Corporate Directory",
                "ldap_entry_uuid",
                "ldap_entry_uuid",
                Map.of(
                        "ldap_entry_uuid",
                        SubjectCanonicalizer.EXACT),
                List.of("ldap_display_name"),
                List.of("ldap_email"),
                List.of(),
                EmailAssurance.AUTHORITATIVE,
                true,
                ProvisioningMode.AUTO,
                ProfileSyncPolicy.defaults());
        ProviderAuthenticationResult result = result(
                new SubjectCandidate(
                        "ldap_entry_uuid",
                        "550e8400-e29b-41d4-a716-446655440000"),
                List.of(),
                Map.of(
                        "ldap_email",
                        values(
                                "alice@example.com",
                                ProviderAttributeTrust.ASSERTED)),
                "ldap");

        IdentityAssertion assertion = factory.create(
                descriptor,
                result);

        assertThat(assertion.profile().email()).contains(
                new EmailClaim(
                        "alice@example.com",
                        EmailAssurance.AUTHORITATIVE));
    }

    @Test
    void rejectsProtocolClaimThatDoesNotMatchTrustedDescriptor() {
        ProviderAuthenticationResult result = result(
                new SubjectCandidate("github_user_id", "123456"),
                List.of(),
                Map.of("login", values("alice", ProviderAttributeTrust.ASSERTED)),
                "oidc"
        );

        assertThatThrownBy(() -> factory.create(githubDescriptor(), result))
                .isInstanceOf(IdentityCoreException.class)
                .extracting("reasonCode")
                .isEqualTo(IdentityFailureCode.INVALID_IDENTITY_ASSERTION);
    }

    @Test
    void rejectsSubjectTypeOutsideTrustedDescriptorAllowlist() {
        ProviderAuthenticationResult result = result(
                new SubjectCandidate("email", "alice@example.com"),
                List.of(),
                Map.of("login", values("alice", ProviderAttributeTrust.ASSERTED)),
                "oauth2-github"
        );

        assertThatThrownBy(() -> factory.create(githubDescriptor(), result))
                .isInstanceOf(IdentityCoreException.class)
                .extracting("reasonCode")
                .isEqualTo(IdentityFailureCode.INVALID_IDENTITY_ASSERTION);
    }

    @Test
    void rejectsNonNumericGithubSubject() {
        ProviderAuthenticationResult result = result(
                new SubjectCandidate("github_user_id", "alice"),
                List.of(),
                Map.of("login", values("alice", ProviderAttributeTrust.ASSERTED)),
                "oauth2-github"
        );

        assertThatThrownBy(() -> factory.create(githubDescriptor(), result))
                .isInstanceOf(IdentityCoreException.class)
                .extracting("reasonCode")
                .isEqualTo(IdentityFailureCode.INVALID_IDENTITY_ASSERTION);
    }

    @Test
    void canonicalizesTypedAliasesForBindingV2() {
        ProviderDescriptor descriptor = new ProviderDescriptor(
                "corp",
                "oidc",
                "https://id.example.com",
                "Corporate Identity",
                "stable_id",
                "legacy_id",
                Map.of(
                        "stable_id",
                        SubjectCanonicalizer.EXACT,
                        "legacy_id",
                        SubjectCanonicalizer.EXACT,
                        "alias_id",
                        SubjectCanonicalizer.EXACT),
                List.of("name"),
                List.of("email"),
                List.of("picture"),
                EmailAssurance.VERIFIED);
        ProviderAuthenticationResult result = result(
                new SubjectCandidate("stable_id", "stable-123"),
                List.of(
                        new SubjectCandidate(
                                "alias_id",
                                "alias-123"),
                        new SubjectCandidate(
                                "legacy_id",
                                "legacy-123")),
                Map.of("login", values("alice", ProviderAttributeTrust.ASSERTED)),
                "oidc"
        );

        IdentityAssertion assertion =
                factory.create(descriptor, result);

        assertThat(assertion.primarySubject()).isEqualTo(
                new ExternalSubject("stable_id", "stable-123"));
        assertThat(assertion.alternateSubjects())
                .containsExactlyInAnyOrder(
                        new ExternalSubject(
                                "alias_id",
                                "alias-123"),
                        new ExternalSubject(
                                "legacy_id",
                                "legacy-123"));
        assertThat(assertion.requireUniqueSubject("legacy_id"))
                .isEqualTo(new ExternalSubject(
                        "legacy_id",
                        "legacy-123"));
    }

    @Test
    void rejectsDuplicateLegacySubjectCandidates() {
        ProviderAuthenticationResult result = result(
                new SubjectCandidate("github_user_id", "123456"),
                List.of(new SubjectCandidate(
                        "github_user_id",
                        "654321")),
                Map.of("login", values(
                        "alice",
                        ProviderAttributeTrust.ASSERTED)),
                "oauth2-github");

        assertThatThrownBy(() ->
                factory.create(githubDescriptor(), result))
                .isInstanceOf(IdentityCoreException.class)
                .extracting("reasonCode")
                .isEqualTo(IdentityFailureCode.INVALID_IDENTITY_ASSERTION);
    }

    @Test
    void rejectsOversizedPrimarySubject() {
        ProviderAuthenticationResult result = result(
                new SubjectCandidate("github_user_id", "1".repeat(257)),
                List.of(),
                Map.of("login", values("alice", ProviderAttributeTrust.ASSERTED)),
                "oauth2-github"
        );

        assertThatThrownBy(() -> factory.create(githubDescriptor(), result))
                .isInstanceOf(IdentityCoreException.class)
                .extracting("reasonCode")
                .isEqualTo(IdentityFailureCode.INVALID_IDENTITY_ASSERTION);
    }

    @Test
    void providerResultDefensivelyCopiesNestedCollections() {
        List<ProviderAttributeValue> loginValues = new ArrayList<>(
                values("alice", ProviderAttributeTrust.ASSERTED));
        Map<String, List<ProviderAttributeValue>> attributes = new HashMap<>();
        attributes.put("login", loginValues);
        Set<String> methods = new java.util.HashSet<>(Set.of("oauth2_authorization_code"));

        ProviderAuthenticationResult result = new ProviderAuthenticationResult(
                new SubjectCandidate("github_user_id", "123456"),
                List.of(),
                attributes,
                new ProtocolAuthenticationEvidence("oauth2-github", AUTHENTICATED_AT, methods)
        );
        loginValues.add(new ProviderAttributeValue("mallory", ProviderAttributeTrust.ASSERTED));
        attributes.put("email", values("mallory@example.com", ProviderAttributeTrust.VERIFIED));
        methods.add("password");

        assertThat(result.attributes()).containsOnlyKeys("login");
        assertThat(result.attributes().get("login")).hasSize(1);
        assertThat(result.evidence().authenticationMethods())
                .containsExactly("oauth2_authorization_code");
        assertThatThrownBy(() -> result.attributes().get("login")
                .add(new ProviderAttributeValue("blocked", ProviderAttributeTrust.ASSERTED)))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    private static ProviderDescriptor githubDescriptor() {
        return new ProviderDescriptor(
                "github",
                "oauth2-github",
                "https://github.com",
                "GitHub",
                "github_user_id",
                "github_user_id",
                Map.of(
                        "github_user_id",
                        SubjectCanonicalizer.DECIMAL),
                List.of("login"),
                List.of("email"),
                List.of("avatar_url"),
                EmailAssurance.VERIFIED
        );
    }

    private static ProviderAuthenticationResult result(
            SubjectCandidate primary,
            List<SubjectCandidate> alternates,
            Map<String, List<ProviderAttributeValue>> attributes,
            String protocol) {
        return new ProviderAuthenticationResult(
                primary,
                alternates,
                attributes,
                new ProtocolAuthenticationEvidence(
                        protocol,
                        AUTHENTICATED_AT,
                        Set.of("oauth2_authorization_code"))
        );
    }

    private static List<ProviderAttributeValue> values(
            String value,
            ProviderAttributeTrust trust) {
        return List.of(new ProviderAttributeValue(value, trust));
    }
}
