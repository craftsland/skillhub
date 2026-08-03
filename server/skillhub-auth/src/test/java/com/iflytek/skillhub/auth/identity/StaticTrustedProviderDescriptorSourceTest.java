package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.iflytek.skillhub.auth.oauth.DingTalkOAuth2Constants;
import com.iflytek.skillhub.auth.oauth.DingTalkProperties;
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

        String providerCode =
                source.resolveBrowserProviderCode(github);
        ProviderDescriptor descriptor = descriptor(source, providerCode);

        assertThat(providerCode).isEqualTo("github");
        assertThat(descriptor.protocol()).isEqualTo("oauth2-github");
        assertThat(descriptor.canonicalAuthority())
                .isEqualTo("https://github.com");
        assertThat(descriptor.primarySubjectType())
                .isEqualTo("github_user_id");
    }

    @Test
    void attachesProviderScopedProvisioningAndProfilePolicies() {
        ClientRegistration github = github();
        OAuth2ClientProperties properties =
                new OAuth2ClientProperties();
        properties.getRegistration().put(
                "github",
                properties("client-id", "GitHub"));
        IdentityProviderPolicyProperties.ProviderPolicy configured =
                new IdentityProviderPolicyProperties.ProviderPolicy();
        configured.setProvisioningMode(
                ProvisioningMode.APPROVAL);
        IdentityProviderPolicyProperties.ProfilePolicy profile =
                new IdentityProviderPolicyProperties.ProfilePolicy();
        profile.setDisplayName(
                ProfileSyncMode.INITIAL_ONLY);
        profile.setEmail(
                ProfileSyncMode.PROVIDER_AUTHORITATIVE);
        profile.setAvatarUrl(ProfileSyncMode.NEVER);
        configured.setProfileSync(profile);
        IdentityProviderPolicyProperties policies =
                new IdentityProviderPolicyProperties();
        policies.setProviders(Map.of("github", configured));
        StaticTrustedProviderDescriptorSource source =
                new StaticTrustedProviderDescriptorSource(
                        properties,
                        new InMemoryClientRegistrationRepository(
                                github),
                        Set.of("github"),
                        policies);

        ProviderDescriptor descriptor = descriptor(source, "github");

        assertThat(descriptor.provisioningMode())
                .isEqualTo(ProvisioningMode.APPROVAL);
        assertThat(descriptor.profileSyncPolicy())
                .isEqualTo(new ProfileSyncPolicy(
                        ProfileSyncMode.INITIAL_ONLY,
                        ProfileSyncMode.PROVIDER_AUTHORITATIVE,
                        ProfileSyncMode.NEVER));
    }

    @Test
    void rejectsReconstructedRegistrationEvenWhenVisibleFieldsMatch() {
        ClientRegistration trustedGithub = github();
        StaticTrustedProviderDescriptorSource source = source(
                Map.of("github", properties("client-id", "GitHub")),
                Set.of("github"),
                trustedGithub);

        assertThatThrownBy(
                () -> source.resolveBrowserProviderCode(github()))
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

        ProviderDescriptor descriptor = descriptor(source, "gitlab");

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
                descriptor(source, "corp-oidc");

        assertThat(descriptor.protocol()).isEqualTo("oidc");
        assertThat(descriptor.canonicalAuthority())
                .isEqualTo("https://id.example.com/tenant");
        assertThat(descriptor.primarySubjectType()).isEqualTo("oidc_sub");
        assertThat(descriptor.legacyPrimarySubjectType())
                .isEqualTo("oidc_sub");
        assertThat(descriptor.canonicalizerFor("oidc_sub"))
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

        assertThat(source.configuredDescriptors()).isEmpty();
        assertThatThrownBy(
                () -> source.resolveBrowserProviderCode(github))
                .isInstanceOf(IdentityCoreException.class)
                .extracting("reasonCode")
                .isEqualTo(IdentityFailureCode.PROVIDER_DISABLED);
        assertThatThrownBy(
                () -> source.resolveBrowserProviderCode(unsupported))
                .isInstanceOf(IdentityCoreException.class)
                .extracting("reasonCode")
                .isEqualTo(IdentityFailureCode.PROVIDER_DISABLED);
    }

    @Test
    void exposesDingTalkOnlyWhenEnabledAndUsesTypedUnionIdAliases() {
        ClientRegistration dingtalk = dingtalk();
        DingTalkProperties dingTalkProperties = new DingTalkProperties();
        dingTalkProperties.setEnabled(true);
        dingTalkProperties.setAuthority("dingtalk.corp");
        OAuth2ClientProperties properties =
                new OAuth2ClientProperties();
        properties.getRegistration().put(
                "dingtalk",
                properties("client-id", "client-secret", "DingTalk"));
        StaticTrustedProviderDescriptorSource source =
                new StaticTrustedProviderDescriptorSource(
                        properties,
                        new InMemoryClientRegistrationRepository(dingtalk),
                        Set.of("dingtalk"),
                        new IdentityProviderPolicyProperties(),
                        dingTalkProperties);

        ProviderDescriptor descriptor = descriptor(source, "dingtalk");

        assertThat(descriptor.protocol()).isEqualTo("dingtalk-oauth2");
        assertThat(descriptor.canonicalAuthority())
                .isEqualTo("dingtalk.corp");
        assertThat(descriptor.primarySubjectType())
                .isEqualTo("dingtalk_union_id");
        assertThat(descriptor.canonicalizerFor("dingtalk_union_id"))
                .isEqualTo(SubjectCanonicalizer.EXACT);
        assertThat(descriptor.canonicalizerFor("dingtalk_open_id"))
                .isEqualTo(SubjectCanonicalizer.EXACT);
        assertThat(descriptor.canonicalizerFor("dingtalk_user_id"))
                .isEqualTo(SubjectCanonicalizer.EXACT);
        assertThat(descriptor.emailAssuranceLimit())
                .isEqualTo(EmailAssurance.PROVIDER_ASSERTED);
    }

    @Test
    void hidesDingTalkWhenDisabledOrEndpointsAreNotOfficial() {
        ClientRegistration dingtalk = dingtalk();
        OAuth2ClientProperties properties = new OAuth2ClientProperties();
        properties.getRegistration().put(
                "dingtalk",
                properties("client-id", "client-secret", "DingTalk"));

        StaticTrustedProviderDescriptorSource disabled =
                new StaticTrustedProviderDescriptorSource(
                        properties,
                        new InMemoryClientRegistrationRepository(dingtalk),
                        Set.of("dingtalk"),
                        new IdentityProviderPolicyProperties(),
                        new DingTalkProperties());
        assertThat(disabled.configuredDescriptors()).isEmpty();

        DingTalkProperties enabled = new DingTalkProperties();
        enabled.setEnabled(true);
        enabled.setAuthority("dingtalk.corp");
        ClientRegistration altered = ClientRegistration.withRegistrationId(
                "dingtalk")
                .clientId("client-id")
                .clientSecret("client-secret")
                .clientName("DingTalk")
                .authorizationGrantType(
                        AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri("https://attacker.example/authorize")
                .tokenUri(DingTalkOAuth2Constants.TOKEN_URI)
                .userInfoUri(DingTalkOAuth2Constants.USER_INFO_URI)
                .userNameAttributeName(
                        DingTalkOAuth2Constants.SUBJECT_ATTRIBUTE)
                .build();
        StaticTrustedProviderDescriptorSource alteredSource =
                new StaticTrustedProviderDescriptorSource(
                        properties,
                        new InMemoryClientRegistrationRepository(altered),
                        Set.of("dingtalk"),
                        new IdentityProviderPolicyProperties(),
                        enabled);
        assertThat(alteredSource.configuredDescriptors()).isEmpty();
    }

    @Test
    void hidesDingTalkWhenClientSecretIsMissingOrPlaceholder() {
        ClientRegistration dingtalk = dingtalk();
        OAuth2ClientProperties properties = new OAuth2ClientProperties();
        properties.getRegistration().put(
                "dingtalk",
                properties("client-id", "placeholder", "DingTalk"));
        DingTalkProperties enabled = new DingTalkProperties();
        enabled.setEnabled(true);
        enabled.setAuthority("dingtalk.corp");

        StaticTrustedProviderDescriptorSource source =
                new StaticTrustedProviderDescriptorSource(
                        properties,
                        new InMemoryClientRegistrationRepository(dingtalk),
                        Set.of("dingtalk"),
                        new IdentityProviderPolicyProperties(),
                        enabled);

        assertThat(source.configuredDescriptors()).isEmpty();
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

        assertThat(source.configuredDescriptors()).isEmpty();
        assertThatThrownBy(
                () -> source.resolveBrowserProviderCode(ambiguous))
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

    private static ProviderDescriptor descriptor(
            StaticTrustedProviderDescriptorSource source,
            String providerCode) {
        return source.configuredDescriptors().stream()
                .filter(candidate -> candidate.providerCode()
                        .equals(providerCode))
                .findFirst()
                .orElseThrow();
    }

    private static OAuth2ClientProperties.Registration properties(
            String clientId,
            String clientName) {
        return properties(clientId, "client-secret", clientName);
    }

    private static OAuth2ClientProperties.Registration properties(
            String clientId,
            String clientSecret,
            String clientName) {
        OAuth2ClientProperties.Registration registration =
                new OAuth2ClientProperties.Registration();
        registration.setClientId(clientId);
        registration.setClientSecret(clientSecret);
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

    private static ClientRegistration dingtalk() {
        return ClientRegistration.withRegistrationId("dingtalk")
                .clientId("client-id")
                .clientSecret("client-secret")
                .clientName("DingTalk")
                .authorizationGrantType(
                        AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope("openid")
                .authorizationUri(
                        DingTalkOAuth2Constants.AUTHORIZATION_URI)
                .tokenUri(DingTalkOAuth2Constants.TOKEN_URI)
                .userInfoUri(DingTalkOAuth2Constants.USER_INFO_URI)
                .userNameAttributeName(
                        DingTalkOAuth2Constants.SUBJECT_ATTRIBUTE)
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
