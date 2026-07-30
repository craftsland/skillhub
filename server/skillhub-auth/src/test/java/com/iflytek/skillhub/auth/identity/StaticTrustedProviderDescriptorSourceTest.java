package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

class StaticTrustedProviderDescriptorSourceTest {

    @Test
    void resolvesConfiguredGithubFromServerOwnedRegistration() {
        ClientRegistration github = github();
        StaticTrustedProviderDescriptorSource source = source(
                Map.of("github", properties("client-id", "GitHub")),
                Set.of("github"),
                github);

        ResolvedProviderHandle handle = source.resolve(github);
        ProviderDescriptor descriptor = source.require(handle);

        assertThat(handle.providerCode()).isEqualTo("github");
        assertThat(descriptor.protocol()).isEqualTo("oauth2-github");
        assertThat(descriptor.canonicalAuthority())
                .isEqualTo("https://github.com");
        assertThat(descriptor.primarySubjectType())
                .isEqualTo("github_user_id");
    }

    @Test
    void rejectsReconstructedRegistrationEvenWhenVisibleFieldsMatch() {
        ClientRegistration trustedGithub = github();
        StaticTrustedProviderDescriptorSource source = source(
                Map.of("github", properties("client-id", "GitHub")),
                Set.of("github"),
                trustedGithub);

        assertThatThrownBy(() -> source.resolve(github()))
                .isInstanceOf(IdentityCoreException.class)
                .extracting("reasonCode")
                .isEqualTo(IdentityFailureCode.PROVIDER_DISABLED);
    }

    @Test
    void derivesSelfManagedGitlabAuthorityFromValidatedEndpoints() {
        ClientRegistration gitlab = gitlab(
                "https://gitlab.example/corp");
        StaticTrustedProviderDescriptorSource source = source(
                Map.of("gitlab", properties("client-id", "Corporate GitLab")),
                Set.of("gitlab"),
                gitlab);

        ProviderDescriptor descriptor =
                source.require(source.resolve(gitlab));

        assertThat(descriptor.protocol()).isEqualTo("oauth2-gitlab");
        assertThat(descriptor.canonicalAuthority())
                .isEqualTo("https://gitlab.example/corp");
        assertThat(descriptor.primarySubjectType())
                .isEqualTo("gitlab_user_id");
    }

    @Test
    void preservesExactOidcIssuerAndCaseSensitiveSubjectRules() {
        ClientRegistration oidc = oidc(
                "corp-oidc",
                "https://id.example.com/tenant");
        StaticTrustedProviderDescriptorSource source = source(
                Map.of("corp-oidc", properties("client-id", "Corporate OIDC")),
                Set.of(),
                oidc);

        ProviderDescriptor descriptor =
                source.require(source.resolve(oidc));

        assertThat(descriptor.protocol()).isEqualTo("oidc");
        assertThat(descriptor.canonicalAuthority())
                .isEqualTo("https://id.example.com/tenant");
        assertThat(descriptor.primarySubjectType()).isEqualTo("oidc_sub");
        assertThat(descriptor.subjectCanonicalizer())
                .isEqualTo(SubjectCanonicalizer.EXACT);
    }

    @Test
    void hidesPlaceholderAndUnsupportedOAuthRegistrations() {
        ClientRegistration github = github();
        ClientRegistration unsupported = oauth(
                "unsupported",
                "https://login.example.com");
        StaticTrustedProviderDescriptorSource source = source(
                Map.of(
                        "github", properties("local-placeholder", "GitHub"),
                        "unsupported",
                        properties("real-client", "Unsupported")),
                Set.of("github"),
                github,
                unsupported);

        assertThat(source.enabledDescriptors()).isEmpty();
        assertThatThrownBy(() -> source.resolve(github))
                .isInstanceOf(IdentityCoreException.class)
                .extracting("reasonCode")
                .isEqualTo(IdentityFailureCode.PROVIDER_DISABLED);
        assertThatThrownBy(() -> source.resolve(unsupported))
                .isInstanceOf(IdentityCoreException.class)
                .extracting("reasonCode")
                .isEqualTo(IdentityFailureCode.PROVIDER_DISABLED);
    }

    @Test
    void rejectsRegistrationThatIsBothOidcAndBackedByOAuthExtractor() {
        ClientRegistration ambiguous = oidc(
                "custom",
                "https://id.example.com");
        StaticTrustedProviderDescriptorSource source = source(
                Map.of("custom", properties("client-id", "Ambiguous")),
                Set.of("custom"),
                ambiguous);

        assertThat(source.enabledDescriptors()).isEmpty();
        assertThatThrownBy(() -> source.resolve(ambiguous))
                .isInstanceOf(IdentityCoreException.class)
                .extracting("reasonCode")
                .isEqualTo(IdentityFailureCode.PROVIDER_DISABLED);
    }

    private static StaticTrustedProviderDescriptorSource source(
            Map<String, OAuth2ClientProperties.Registration> registrations,
            Set<String> extractorCodes,
            ClientRegistration... clientRegistrations) {
        OAuth2ClientProperties properties = new OAuth2ClientProperties();
        properties.getRegistration().putAll(registrations);
        return new StaticTrustedProviderDescriptorSource(
                properties,
                new InMemoryClientRegistrationRepository(clientRegistrations),
                extractorCodes);
    }

    private static OAuth2ClientProperties.Registration properties(
            String clientId,
            String clientName) {
        OAuth2ClientProperties.Registration registration =
                new OAuth2ClientProperties.Registration();
        registration.setClientId(clientId);
        registration.setClientName(clientName);
        return registration;
    }

    private static ClientRegistration github() {
        return ClientRegistration.withRegistrationId("github")
                .clientId("client-id")
                .clientSecret("client-secret")
                .clientName("GitHub")
                .authorizationGrantType(
                        AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri(
                        "https://github.com/login/oauth/authorize")
                .tokenUri(
                        "https://github.com/login/oauth/access_token")
                .userInfoUri("https://api.github.com/user")
                .userNameAttributeName("id")
                .build();
    }

    private static ClientRegistration gitlab(String authority) {
        return ClientRegistration.withRegistrationId("gitlab")
                .clientId("client-id")
                .clientSecret("client-secret")
                .clientName("GitLab")
                .authorizationGrantType(
                        AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri(authority + "/oauth/authorize")
                .tokenUri(authority + "/oauth/token")
                .userInfoUri(authority + "/api/v4/user")
                .userNameAttributeName("username")
                .build();
    }

    private static ClientRegistration oidc(
            String registrationId,
            String issuer) {
        return ClientRegistration.withRegistrationId(registrationId)
                .clientId("client-id")
                .clientSecret("client-secret")
                .clientName("OIDC")
                .authorizationGrantType(
                        AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .issuerUri(issuer)
                .authorizationUri(issuer + "/authorize")
                .tokenUri(issuer + "/token")
                .jwkSetUri(issuer + "/jwks")
                .userInfoUri(issuer + "/userinfo")
                .userNameAttributeName("sub")
                .scope("openid")
                .build();
    }

    private static ClientRegistration oauth(
            String registrationId,
            String authority) {
        return ClientRegistration.withRegistrationId(registrationId)
                .clientId("client-id")
                .clientSecret("client-secret")
                .clientName(registrationId)
                .authorizationGrantType(
                        AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri(authority + "/authorize")
                .tokenUri(authority + "/token")
                .userInfoUri(authority + "/userinfo")
                .userNameAttributeName("id")
                .build();
    }
}
