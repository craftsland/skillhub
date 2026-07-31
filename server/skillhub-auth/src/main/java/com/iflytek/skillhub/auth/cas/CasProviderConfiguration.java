package com.iflytek.skillhub.auth.cas;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Component;

/**
 * Fail-closed resolver for the trusted CAS provider configuration.
 */
@Component
final class CasProviderConfiguration {

    private static final Pattern PROVIDER_CODE_PATTERN =
            Pattern.compile("[a-z0-9][a-z0-9._-]{0,63}");
    private static final Pattern AUTHORITY_PATTERN =
            Pattern.compile("[a-z0-9][a-z0-9._:-]{0,127}");
    private static final Pattern SUBJECT_TYPE_PATTERN =
            Pattern.compile("[a-z][a-z0-9_]{0,63}");
    private static final Pattern ATTRIBUTE_PATTERN =
            Pattern.compile("[A-Za-z][A-Za-z0-9_.:-]{0,127}");
    private static final Duration MAX_NETWORK_TIMEOUT =
            Duration.ofMinutes(1);
    private static final Duration MAX_STATE_TTL =
            Duration.ofMinutes(15);

    private final CasProperties properties;
    private final Environment environment;

    CasProviderConfiguration(
            CasProperties properties,
            Environment environment) {
        this.properties = properties;
        this.environment = environment;
    }

    boolean enabled() {
        return properties.isEnabled();
    }

    String configuredProviderCode() {
        return properties.getProviderCode();
    }

    ResolvedCasProvider requireResolved() {
        if (!properties.isEnabled()) {
            throw invalidConfiguration();
        }

        String providerCode = requireMatching(
                properties.getProviderCode(),
                PROVIDER_CODE_PATTERN);
        String displayName = requireText(
                properties.getDisplayName(),
                128);
        String authority = requireMatching(
                properties.getAuthority(),
                AUTHORITY_PATTERN);
        String subjectType = requireMatching(
                properties.getSubjectType(),
                SUBJECT_TYPE_PATTERN);
        URI serverUri = requireEndpoint(
                properties.getServerUrl(),
                false);
        URI serviceUri = requireEndpoint(
                properties.getServiceUrl(),
                true);
        requireCallbackPath(serviceUri, providerCode);

        CasProtocolVersion protocolVersion;
        try {
            protocolVersion = CasProtocolVersion.parse(
                    properties.getProtocolVersion());
        } catch (RuntimeException exception) {
            throw invalidConfiguration();
        }

        CasProperties.Attributes attributes =
                Objects.requireNonNull(properties.getAttributes());
        Optional<String> subjectAttribute =
                optionalAttribute(attributes.getSubject());
        Optional<String> displayNameAttribute =
                optionalAttribute(attributes.getDisplayName());
        Optional<String> emailAttribute =
                optionalAttribute(attributes.getEmail());
        Optional<String> avatarAttribute =
                optionalAttribute(attributes.getAvatarUrl());

        Duration connectTimeout = requireDuration(
                properties.getConnectTimeout(),
                MAX_NETWORK_TIMEOUT);
        Duration readTimeout = requireDuration(
                properties.getReadTimeout(),
                MAX_NETWORK_TIMEOUT);
        Duration stateTtl = requireDuration(
                properties.getStateTtl(),
                MAX_STATE_TTL);
        int maximumResponseBytes = properties.getMaxResponseBytes();
        if (maximumResponseBytes < 1024
                || maximumResponseBytes > 1024 * 1024) {
            throw invalidConfiguration();
        }

        return new ResolvedCasProvider(
                providerCode,
                displayName,
                authority,
                serverUri,
                serviceUri,
                protocolVersion,
                subjectType,
                subjectAttribute,
                displayNameAttribute,
                emailAttribute,
                avatarAttribute,
                connectTimeout,
                readTimeout,
                stateTtl,
                maximumResponseBytes);
    }

    private URI requireEndpoint(
            String value,
            boolean service) {
        if (value == null || value.isBlank()
                || !value.equals(value.strip())) {
            throw invalidConfiguration();
        }
        URI uri;
        try {
            uri = new URI(value);
        } catch (URISyntaxException exception) {
            throw invalidConfiguration();
        }
        if (!uri.isAbsolute()
                || uri.getHost() == null
                || uri.getUserInfo() != null
                || uri.getFragment() != null
                || uri.getQuery() != null
                || uri.getPort() == 0
                || uri.getPort() > 65535) {
            throw invalidConfiguration();
        }
        String scheme = uri.getScheme();
        if ("https".equalsIgnoreCase(scheme)) {
            return uri;
        }
        if (!"http".equalsIgnoreCase(scheme)
                || !properties.isAllowInsecureForTesting()
                || !environment.acceptsProfiles(Profiles.of(
                        "local",
                        "test",
                        "staging"))) {
            throw invalidConfiguration();
        }
        return uri;
    }

    private void requireCallbackPath(
            URI serviceUri,
            String providerCode) {
        String expectedSuffix = "/api/v1/auth/cas/"
                + providerCode
                + "/callback";
        if (!serviceUri.getPath().endsWith(expectedSuffix)) {
            throw invalidConfiguration();
        }
    }

    private String requireMatching(
            String value,
            Pattern pattern) {
        if (value == null || !pattern.matcher(value).matches()) {
            throw invalidConfiguration();
        }
        return value;
    }

    private String requireText(
            String value,
            int maximumLength) {
        if (value == null
                || value.isBlank()
                || value.length() > maximumLength
                || !value.equals(value.strip())) {
            throw invalidConfiguration();
        }
        return value;
    }

    private Optional<String> optionalAttribute(String value) {
        if (value == null || value.isEmpty()) {
            return Optional.empty();
        }
        if (!value.equals(value.strip())
                || !ATTRIBUTE_PATTERN.matcher(value).matches()) {
            throw invalidConfiguration();
        }
        return Optional.of(value);
    }

    private Duration requireDuration(
            Duration value,
            Duration maximum) {
        if (value == null
                || value.isZero()
                || value.isNegative()
                || value.compareTo(maximum) > 0) {
            throw invalidConfiguration();
        }
        return value;
    }

    private IllegalArgumentException invalidConfiguration() {
        return new IllegalArgumentException(
                "Invalid CAS provider configuration");
    }

    record ResolvedCasProvider(
            String providerCode,
            String displayName,
            String authority,
            URI serverUri,
            URI serviceUri,
            CasProtocolVersion protocolVersion,
            String subjectType,
            Optional<String> subjectAttribute,
            Optional<String> displayNameAttribute,
            Optional<String> emailAttribute,
            Optional<String> avatarAttribute,
            Duration connectTimeout,
            Duration readTimeout,
            Duration stateTtl,
            int maximumResponseBytes
    ) {
    }
}
