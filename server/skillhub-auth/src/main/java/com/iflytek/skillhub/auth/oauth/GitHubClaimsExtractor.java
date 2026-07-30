package com.iflytek.skillhub.auth.oauth;

import com.iflytek.skillhub.auth.identity.ProtocolAuthenticationEvidence;
import com.iflytek.skillhub.auth.identity.ProviderAttributeTrust;
import com.iflytek.skillhub.auth.identity.ProviderAttributeValue;
import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;
import com.iflytek.skillhub.auth.identity.SubjectCandidate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Provider-specific claims extractor that enriches GitHub OAuth users with their primary verified
 * email when necessary.
 */
@Component
public class GitHubClaimsExtractor implements OAuthClaimsExtractor {

    private final RestClient restClient;

    public GitHubClaimsExtractor(RestClient.Builder restClientBuilder) {
        this.restClient = restClientBuilder
            .baseUrl("https://api.github.com")
            .defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .build();
    }

    @Override
    public String getProvider() { return "github"; }

    @Override
    public ProviderAuthenticationResult extract(
            OAuth2UserRequest request,
            OAuth2User oAuth2User) {
        Map<String, Object> attrs = oAuth2User.getAttributes();
        GitHubEmail primaryEmail = loadPrimaryEmail(request);
        String email = primaryEmail != null ? primaryEmail.email() : (String) attrs.get("email");
        boolean emailVerified = primaryEmail != null && primaryEmail.verified();

        Map<String, List<ProviderAttributeValue>> attributes =
                new LinkedHashMap<>();
        put(attributes, "login", attrs.get("login"), ProviderAttributeTrust.ASSERTED);
        put(
                attributes,
                "email",
                email,
                emailVerified
                        ? ProviderAttributeTrust.VERIFIED
                        : ProviderAttributeTrust.UNVERIFIED);
        put(
                attributes,
                "avatar_url",
                attrs.get("avatar_url"),
                ProviderAttributeTrust.ASSERTED);

        return new ProviderAuthenticationResult(
                new SubjectCandidate(
                        "github_user_id",
                        String.valueOf(attrs.get("id"))),
                List.of(),
                attributes,
                new ProtocolAuthenticationEvidence(
                        "oauth2-github",
                        request.getAccessToken().getIssuedAt(),
                        Set.of("oauth2_authorization_code")));
    }

    private void put(
            Map<String, List<ProviderAttributeValue>> attributes,
            String key,
            Object rawValue,
            ProviderAttributeTrust trust) {
        if (!(rawValue instanceof String value) || value.isBlank()) {
            return;
        }
        attributes.put(
                key,
                List.of(new ProviderAttributeValue(value, trust)));
    }

    private GitHubEmail loadPrimaryEmail(OAuth2UserRequest request) {
        List<GitHubEmail> emails = restClient.get()
            .uri("/user/emails")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + request.getAccessToken().getTokenValue())
            .retrieve()
            .body(new org.springframework.core.ParameterizedTypeReference<List<GitHubEmail>>() {});

        if (emails == null || emails.isEmpty()) {
            return null;
        }

        return emails.stream()
            .filter(GitHubEmail::verified)
            .sorted(Comparator.comparing(GitHubEmail::primary).reversed())
            .findFirst()
            .orElse(null);
    }

    private record GitHubEmail(String email, boolean primary, boolean verified) {}
}
