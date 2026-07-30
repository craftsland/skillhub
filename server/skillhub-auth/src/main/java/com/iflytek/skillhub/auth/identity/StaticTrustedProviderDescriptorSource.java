package com.iflytek.skillhub.auth.identity;

import com.iflytek.skillhub.auth.oauth.OAuthClaimsExtractor;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Component;

/**
 * Transitional trusted descriptor source for the existing GitHub, GitLab and
 * OIDC Spring Security registrations.
 */
@Component
class StaticTrustedProviderDescriptorSource
        implements TrustedProviderDescriptorSource,
        TrustedProviderRouteResolver {

    private static final Logger log = LoggerFactory.getLogger(
            StaticTrustedProviderDescriptorSource.class);

    private final Map<String, ProviderDescriptor> descriptors;
    private final Map<String, ClientRegistration> trustedRegistrations;

    @Autowired
    StaticTrustedProviderDescriptorSource(
            OAuth2ClientProperties properties,
            ClientRegistrationRepository registrationRepository,
            List<OAuthClaimsExtractor> extractors) {
        this(
                properties,
                registrationRepository,
                extractors.stream()
                        .map(OAuthClaimsExtractor::getProvider)
                        .collect(Collectors.toUnmodifiableSet()));
    }

    StaticTrustedProviderDescriptorSource(
            OAuth2ClientProperties properties,
            ClientRegistrationRepository registrationRepository,
            Set<String> extractorCodes) {
        Map<String, ProviderDescriptor> resolvedDescriptors =
                new LinkedHashMap<>();
        Map<String, ClientRegistration> resolvedRegistrations =
                new LinkedHashMap<>();

        properties.getRegistration().entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(entry -> resolveConfiguredRegistration(
                        entry.getKey(),
                        entry.getValue(),
                        registrationRepository,
                        extractorCodes).ifPresent(resolved -> {
                            resolvedDescriptors.put(
                                    entry.getKey(),
                                    resolved.descriptor());
                            resolvedRegistrations.put(
                                    entry.getKey(),
                                    resolved.registration());
                        }));
        descriptors = Map.copyOf(resolvedDescriptors);
        trustedRegistrations = Map.copyOf(resolvedRegistrations);
    }

    @Override
    public ResolvedProviderHandle resolve(
            ClientRegistration registration) {
        if (registration == null) {
            throw providerDisabled();
        }
        String providerCode = registration.getRegistrationId();
        ClientRegistration trusted = trustedRegistrations.get(providerCode);
        // Spring Boot's static OAuth client configuration uses the canonical
        // ClientRegistration instances held by its in-memory repository.
        // Matching selected fields would let a reconstructed object omit or
        // replace other security-relevant registration fields.
        if (trusted == null || trusted != registration) {
            throw providerDisabled();
        }
        return new DefaultResolvedProviderHandle(providerCode);
    }

    @Override
    public ProviderDescriptor require(ResolvedProviderHandle provider) {
        if (!(provider instanceof DefaultResolvedProviderHandle handle)) {
            throw providerDisabled();
        }
        ProviderDescriptor descriptor =
                descriptors.get(handle.providerCode());
        if (descriptor == null) {
            throw providerDisabled();
        }
        return descriptor;
    }

    @Override
    public List<ProviderDescriptor> enabledDescriptors() {
        return descriptors.values().stream()
                .sorted(Comparator.comparing(
                        ProviderDescriptor::providerCode))
                .toList();
    }

    private Optional<ResolvedDescriptor> resolveConfiguredRegistration(
            String providerCode,
            OAuth2ClientProperties.Registration properties,
            ClientRegistrationRepository registrationRepository,
            Set<String> extractorCodes) {
        if (!hasRealClientId(properties.getClientId())) {
            return Optional.empty();
        }
        ClientRegistration registration;
        try {
            registration = registrationRepository
                    .findByRegistrationId(providerCode);
        } catch (RuntimeException exception) {
            log.warn(
                    "Identity provider '{}' is hidden because its client registration cannot be resolved",
                    providerCode);
            return Optional.empty();
        }
        if (registration == null) {
            return Optional.empty();
        }

        try {
            ProviderDescriptor descriptor = descriptorFor(
                    providerCode,
                    registration,
                    extractorCodes);
            return Optional.of(new ResolvedDescriptor(
                    descriptor,
                    registration));
        } catch (IllegalArgumentException exception) {
            log.warn(
                    "Identity provider '{}' is hidden because its trusted descriptor is invalid",
                    providerCode);
            return Optional.empty();
        }
    }

    private ProviderDescriptor descriptorFor(
            String providerCode,
            ClientRegistration registration,
            Set<String> extractorCodes) {
        String issuer = registration.getProviderDetails().getIssuerUri();
        boolean hasIssuer = issuer != null && !issuer.isBlank();
        boolean hasExtractor = extractorCodes.contains(providerCode);
        if (hasIssuer && hasExtractor) {
            throw new IllegalArgumentException(
                    "Ambiguous OAuth and OIDC registration");
        }

        return switch (providerCode) {
            case "github" -> {
                if (!hasExtractor || hasIssuer) {
                    throw new IllegalArgumentException(
                            "GitHub extractor is unavailable");
                }
                validatePublicGithubEndpoints(registration);
                yield descriptor(
                        providerCode,
                        "oauth2-github",
                        "https://github.com",
                        registration.getClientName(),
                        "github_user_id",
                        SubjectCanonicalizer.DECIMAL,
                        List.of("login"),
                        List.of("email"),
                        List.of("avatar_url"));
            }
            case "gitlab" -> {
                if (!hasExtractor || hasIssuer) {
                    throw new IllegalArgumentException(
                            "GitLab extractor is unavailable");
                }
                String authority = deriveGitlabAuthority(registration);
                yield descriptor(
                        providerCode,
                        "oauth2-gitlab",
                        authority,
                        registration.getClientName(),
                        "gitlab_user_id",
                        SubjectCanonicalizer.DECIMAL,
                        List.of("username", "login"),
                        List.of("email"),
                        List.of("avatar_url"));
            }
            default -> {
                if (!hasIssuer || hasExtractor) {
                    throw new IllegalArgumentException(
                            "Unsupported OAuth registration");
                }
                validateIssuer(issuer);
                yield descriptor(
                        providerCode,
                        "oidc",
                        issuer,
                        registration.getClientName(),
                        "oidc_sub",
                        SubjectCanonicalizer.EXACT,
                        List.of(
                                "preferred_username",
                                "name",
                                "email",
                                "sub"),
                        List.of("email"),
                        List.of("picture", "avatar_url"));
            }
        };
    }

    private ProviderDescriptor descriptor(
            String providerCode,
            String protocol,
            String authority,
            String configuredDisplayName,
            String subjectType,
            SubjectCanonicalizer canonicalizer,
            List<String> displayNameAttributes,
            List<String> emailAttributes,
            List<String> avatarAttributes) {
        String displayName =
                configuredDisplayName == null
                        || configuredDisplayName.isBlank()
                        ? providerCode
                        : configuredDisplayName;
        return new ProviderDescriptor(
                providerCode,
                protocol,
                authority,
                displayName,
                subjectType,
                subjectType,
                Map.of(subjectType, canonicalizer),
                displayNameAttributes,
                emailAttributes,
                avatarAttributes,
                EmailAssurance.VERIFIED);
    }

    private void validatePublicGithubEndpoints(
            ClientRegistration registration) {
        var details = registration.getProviderDetails();
        if (!"https://github.com/login/oauth/authorize".equals(
                details.getAuthorizationUri())
                || !"https://github.com/login/oauth/access_token".equals(
                details.getTokenUri())
                || !"https://api.github.com/user".equals(
                details.getUserInfoEndpoint().getUri())) {
            throw new IllegalArgumentException(
                    "Only public GitHub is supported by the built-in adapter");
        }
    }

    private String deriveGitlabAuthority(
            ClientRegistration registration) {
        String authorizationUri =
                registration.getProviderDetails().getAuthorizationUri();
        URI parsed = parseAuthorityUri(authorizationUri);
        String suffix = "/oauth/authorize";
        if (!parsed.getPath().endsWith(suffix)) {
            throw new IllegalArgumentException(
                    "Invalid GitLab authorization endpoint");
        }
        String authorityPath = parsed.getPath().substring(
                0,
                parsed.getPath().length() - suffix.length());
        try {
            URI authorityUri = new URI(
                    parsed.getScheme(),
                    null,
                    parsed.getHost(),
                    parsed.getPort(),
                    authorityPath.isEmpty() ? null : authorityPath,
                    null,
                    null);
            String authority = authorityUri.toString();
            validateAuthorityScheme(authorityUri);
            if (!(authority + "/oauth/token").equals(
                    registration.getProviderDetails().getTokenUri())
                    || !(authority + "/api/v4/user").equals(
                    registration.getProviderDetails()
                            .getUserInfoEndpoint()
                            .getUri())) {
                throw new IllegalArgumentException(
                        "GitLab endpoints do not share one authority");
            }
            return authority;
        } catch (URISyntaxException exception) {
            throw new IllegalArgumentException(
                    "Invalid GitLab authority",
                    exception);
        }
    }

    private void validateIssuer(String issuer) {
        URI uri = parseAuthorityUri(issuer);
        validateAuthorityScheme(uri);
    }

    private URI parseAuthorityUri(String value) {
        try {
            URI uri = new URI(value);
            if (!uri.isAbsolute()
                    || uri.getHost() == null
                    || uri.getRawUserInfo() != null
                    || uri.getRawQuery() != null
                    || uri.getRawFragment() != null) {
                throw new IllegalArgumentException(
                        "Invalid authority URI");
            }
            return uri;
        } catch (URISyntaxException exception) {
            throw new IllegalArgumentException(
                    "Invalid authority URI",
                    exception);
        }
    }

    private void validateAuthorityScheme(URI uri) {
        if ("https".equalsIgnoreCase(uri.getScheme())) {
            return;
        }
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        if ("http".equalsIgnoreCase(uri.getScheme())
                && ("localhost".equals(host)
                || "127.0.0.1".equals(host)
                || "::1".equals(host))) {
            return;
        }
        throw new IllegalArgumentException(
                "Provider authority must use HTTPS");
    }

    private boolean hasRealClientId(String clientId) {
        return clientId != null
                && !clientId.isBlank()
                && !clientId.toLowerCase(Locale.ROOT)
                        .contains("placeholder");
    }

    private IdentityCoreException providerDisabled() {
        return new IdentityCoreException(
                IdentityFailureCode.PROVIDER_DISABLED);
    }

    private record ResolvedDescriptor(
            ProviderDescriptor descriptor,
            ClientRegistration registration) {
    }
}
