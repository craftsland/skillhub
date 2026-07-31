package com.iflytek.skillhub.auth.ldap;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Component;

/**
 * Fail-closed resolver for the trusted LDAP provider configuration.
 */
@Component
final class LdapProviderConfiguration {

    private static final Pattern PROVIDER_CODE_PATTERN =
            Pattern.compile("[a-z0-9][a-z0-9._-]{0,63}");
    private static final Pattern AUTHORITY_PATTERN =
            Pattern.compile("[a-z0-9][a-z0-9._:-]{0,127}");
    private static final Pattern SUBJECT_TYPE_PATTERN =
            Pattern.compile("[a-z][a-z0-9_]{0,63}");
    private static final Pattern ATTRIBUTE_PATTERN =
            Pattern.compile("[A-Za-z][A-Za-z0-9_.;:-]{0,127}");
    private static final Duration MAX_NETWORK_TIMEOUT =
            Duration.ofMinutes(1);
    private static final int MAX_SECRET_LENGTH = 4096;
    private static final int MAX_DN_LENGTH = 2048;
    private static final int MAX_FILTER_LENGTH = 1024;
    private static final Set<String> UNSTABLE_SUBJECT_NAMES = Set.of(
            "uid",
            "mail",
            "email",
            "username",
            "userprincipalname",
            "samaccountname",
            "cn",
            "displayname",
            "dn",
            "distinguishedname",
            "entrydn",
            "uidnumber",
            "employeenumber");

    private final LdapProperties properties;
    private final Environment environment;

    LdapProviderConfiguration(
            LdapProperties properties,
            Environment environment) {
        this.properties = properties;
        this.environment = environment;
    }

    boolean enabled() {
        return properties.isEnabled();
    }

    ResolvedLdapProvider requireResolved() {
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
        URI endpoint = requireEndpoint(properties.getUrl());
        LdapTransport transport = resolveTransport(endpoint);
        LdapDirectoryType directoryType = parseDirectoryType(
                properties.getDirectoryType());
        String baseDn = requireDn(properties.getBaseDn(), false);
        String userSearchBase = requireDn(
                properties.getUserSearchBase(),
                true);
        String userSearchFilter = requireSearchFilter(
                properties.getUserSearchFilter());
        String bindDn = requireDn(properties.getBindDn(), false);
        String bindPassword = requireSecret(
                properties.getBindPassword());

        String subjectAttribute = optionalAttribute(
                properties.getSubjectAttribute())
                .orElseGet(() -> defaultSubjectAttribute(directoryType));
        String subjectType = optionalSubjectType(
                properties.getSubjectType())
                .orElseGet(() -> defaultSubjectType(directoryType));
        validateSubjectMapping(subjectAttribute, subjectType);
        Optional<String> usernameAttribute = optionalAttribute(
                properties.getUsernameAttribute());
        Optional<String> displayNameAttribute = optionalAttribute(
                properties.getDisplayNameAttribute());
        Optional<String> emailAttribute = optionalAttribute(
                properties.getEmailAttribute());
        Optional<String> avatarUrlAttribute = optionalAttribute(
                properties.getAvatarUrlAttribute());

        Duration connectTimeout = requireDuration(
                properties.getConnectTimeout());
        Duration readTimeout = requireDuration(
                properties.getReadTimeout());
        Duration poolWaitTimeout = requireDuration(
                properties.getPoolWaitTimeout());
        int maximumConcurrentRequests =
                properties.getMaxConcurrentRequests();
        if (maximumConcurrentRequests < 1
                || maximumConcurrentRequests > 256) {
            throw invalidConfiguration();
        }
        int maximumAttributeValues = properties.getMaxAttributeValues();
        if (maximumAttributeValues < 1
                || maximumAttributeValues > 64) {
            throw invalidConfiguration();
        }

        Set<String> requestedAttributes = new LinkedHashSet<>();
        requestedAttributes.add(subjectAttribute);
        usernameAttribute.ifPresent(requestedAttributes::add);
        displayNameAttribute.ifPresent(requestedAttributes::add);
        emailAttribute.ifPresent(requestedAttributes::add);
        avatarUrlAttribute.ifPresent(requestedAttributes::add);

        return new ResolvedLdapProvider(
                providerCode,
                displayName,
                authority,
                endpoint,
                transport,
                directoryType,
                baseDn,
                userSearchBase,
                userSearchFilter,
                bindDn,
                bindPassword,
                subjectAttribute,
                subjectType,
                usernameAttribute,
                displayNameAttribute,
                emailAttribute,
                avatarUrlAttribute,
                properties.isEmailAuthoritative(),
                connectTimeout,
                readTimeout,
                poolWaitTimeout,
                maximumConcurrentRequests,
                maximumAttributeValues,
                Set.copyOf(requestedAttributes));
    }

    private URI requireEndpoint(String value) {
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
                || uri.getQuery() != null
                || uri.getFragment() != null
                || uri.getPort() == 0
                || uri.getPort() > 65535
                || !(uri.getPath().isEmpty()
                || "/".equals(uri.getPath()))) {
            throw invalidConfiguration();
        }
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        if (!"ldap".equals(scheme) && !"ldaps".equals(scheme)) {
            throw invalidConfiguration();
        }
        return uri;
    }

    private LdapTransport resolveTransport(URI endpoint) {
        if ("ldaps".equalsIgnoreCase(endpoint.getScheme())) {
            if (properties.isStartTls()) {
                throw invalidConfiguration();
            }
            return LdapTransport.LDAPS;
        }
        if (properties.isStartTls()) {
            return LdapTransport.STARTTLS;
        }
        if (!properties.isAllowInsecureForTesting()
                || !environment.acceptsProfiles(Profiles.of(
                        "local",
                        "test",
                        "staging"))) {
            throw invalidConfiguration();
        }
        return LdapTransport.PLAIN;
    }

    private LdapDirectoryType parseDirectoryType(String value) {
        try {
            return LdapDirectoryType.valueOf(
                    requireText(value, 32)
                            .toUpperCase(Locale.ROOT));
        } catch (RuntimeException exception) {
            throw invalidConfiguration();
        }
    }

    private String defaultSubjectAttribute(
            LdapDirectoryType directoryType) {
        return switch (directoryType) {
            case OPENLDAP -> "entryUUID";
            case ACTIVE_DIRECTORY -> "objectGUID";
            case CUSTOM -> throw invalidConfiguration();
        };
    }

    private String defaultSubjectType(
            LdapDirectoryType directoryType) {
        return switch (directoryType) {
            case OPENLDAP -> "ldap_entry_uuid";
            case ACTIVE_DIRECTORY -> "ad_object_guid";
            case CUSTOM -> throw invalidConfiguration();
        };
    }

    private String requireSearchFilter(String value) {
        String filter = requireText(value, MAX_FILTER_LENGTH);
        if (count(filter, "{0}") != 1
                || filter.contains("{1}")) {
            throw invalidConfiguration();
        }
        try {
            Filter.create(filter.replace(
                    "{0}",
                    Filter.encodeValue("skillhub-probe")));
        } catch (LDAPException exception) {
            throw invalidConfiguration();
        }
        return filter;
    }

    private int count(String value, String needle) {
        int count = 0;
        int offset = 0;
        while ((offset = value.indexOf(needle, offset)) >= 0) {
            count++;
            offset += needle.length();
        }
        return count;
    }

    private String requireDn(String value, boolean allowEmpty) {
        if (allowEmpty && value != null && value.isEmpty()) {
            return value;
        }
        String dn = requireText(value, MAX_DN_LENGTH);
        if (dn.chars().anyMatch(Character::isISOControl)) {
            throw invalidConfiguration();
        }
        try {
            new DN(dn);
        } catch (LDAPException exception) {
            throw invalidConfiguration();
        }
        return dn;
    }

    private String requireSecret(String value) {
        if (value == null
                || value.isBlank()
                || value.length() > MAX_SECRET_LENGTH
                || value.chars().anyMatch(Character::isISOControl)) {
            throw invalidConfiguration();
        }
        return value;
    }

    private String requireMatching(String value, Pattern pattern) {
        if (value == null || !pattern.matcher(value).matches()) {
            throw invalidConfiguration();
        }
        return value;
    }

    private String requireText(String value, int maximumLength) {
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

    private Optional<String> optionalSubjectType(String value) {
        if (value == null || value.isEmpty()) {
            return Optional.empty();
        }
        if (!SUBJECT_TYPE_PATTERN.matcher(value).matches()) {
            throw invalidConfiguration();
        }
        return Optional.of(value);
    }

    private void validateSubjectMapping(
            String subjectAttribute,
            String subjectType) {
        if (isUnstableSubjectName(subjectAttribute)
                || isUnstableSubjectName(subjectType)) {
            throw invalidConfiguration();
        }
    }

    private boolean isUnstableSubjectName(String value) {
        String normalized = value
                .toLowerCase(Locale.ROOT)
                .replace("_", "")
                .replace("-", "");
        return UNSTABLE_SUBJECT_NAMES.contains(normalized);
    }

    private Duration requireDuration(Duration value) {
        if (value == null
                || value.isZero()
                || value.isNegative()
                || value.compareTo(MAX_NETWORK_TIMEOUT) > 0) {
            throw invalidConfiguration();
        }
        return value;
    }

    private IllegalArgumentException invalidConfiguration() {
        return new IllegalArgumentException(
                "Invalid LDAP provider configuration");
    }

    /**
     * Validated provider data. Deliberately not a record so its generated
     * {@code toString()} cannot disclose the service-account password.
     */
    static final class ResolvedLdapProvider {

        private final String providerCode;
        private final String displayName;
        private final String authority;
        private final URI endpoint;
        private final LdapTransport transport;
        private final LdapDirectoryType directoryType;
        private final String baseDn;
        private final String userSearchBase;
        private final String userSearchFilter;
        private final String bindDn;
        private final String bindPassword;
        private final String subjectAttribute;
        private final String subjectType;
        private final Optional<String> usernameAttribute;
        private final Optional<String> displayNameAttribute;
        private final Optional<String> emailAttribute;
        private final Optional<String> avatarUrlAttribute;
        private final boolean emailAuthoritative;
        private final Duration connectTimeout;
        private final Duration readTimeout;
        private final Duration poolWaitTimeout;
        private final int maximumConcurrentRequests;
        private final int maximumAttributeValues;
        private final Set<String> requestedAttributes;

        private ResolvedLdapProvider(
                String providerCode,
                String displayName,
                String authority,
                URI endpoint,
                LdapTransport transport,
                LdapDirectoryType directoryType,
                String baseDn,
                String userSearchBase,
                String userSearchFilter,
                String bindDn,
                String bindPassword,
                String subjectAttribute,
                String subjectType,
                Optional<String> usernameAttribute,
                Optional<String> displayNameAttribute,
                Optional<String> emailAttribute,
                Optional<String> avatarUrlAttribute,
                boolean emailAuthoritative,
                Duration connectTimeout,
                Duration readTimeout,
                Duration poolWaitTimeout,
                int maximumConcurrentRequests,
                int maximumAttributeValues,
                Set<String> requestedAttributes) {
            this.providerCode = providerCode;
            this.displayName = displayName;
            this.authority = authority;
            this.endpoint = endpoint;
            this.transport = transport;
            this.directoryType = directoryType;
            this.baseDn = baseDn;
            this.userSearchBase = userSearchBase;
            this.userSearchFilter = userSearchFilter;
            this.bindDn = bindDn;
            this.bindPassword = bindPassword;
            this.subjectAttribute = subjectAttribute;
            this.subjectType = subjectType;
            this.usernameAttribute = usernameAttribute;
            this.displayNameAttribute = displayNameAttribute;
            this.emailAttribute = emailAttribute;
            this.avatarUrlAttribute = avatarUrlAttribute;
            this.emailAuthoritative = emailAuthoritative;
            this.connectTimeout = connectTimeout;
            this.readTimeout = readTimeout;
            this.poolWaitTimeout = poolWaitTimeout;
            this.maximumConcurrentRequests = maximumConcurrentRequests;
            this.maximumAttributeValues = maximumAttributeValues;
            this.requestedAttributes = requestedAttributes;
        }

        String providerCode() {
            return providerCode;
        }

        String displayName() {
            return displayName;
        }

        String authority() {
            return authority;
        }

        URI endpoint() {
            return endpoint;
        }

        LdapTransport transport() {
            return transport;
        }

        LdapDirectoryType directoryType() {
            return directoryType;
        }

        String baseDn() {
            return baseDn;
        }

        String userSearchBase() {
            return userSearchBase;
        }

        String userSearchFilter() {
            return userSearchFilter;
        }

        String bindDn() {
            return bindDn;
        }

        String bindPassword() {
            return bindPassword;
        }

        String subjectAttribute() {
            return subjectAttribute;
        }

        String subjectType() {
            return subjectType;
        }

        Optional<String> usernameAttribute() {
            return usernameAttribute;
        }

        Optional<String> displayNameAttribute() {
            return displayNameAttribute;
        }

        Optional<String> emailAttribute() {
            return emailAttribute;
        }

        Optional<String> avatarUrlAttribute() {
            return avatarUrlAttribute;
        }

        boolean emailAuthoritative() {
            return emailAuthoritative;
        }

        Duration connectTimeout() {
            return connectTimeout;
        }

        Duration readTimeout() {
            return readTimeout;
        }

        Duration poolWaitTimeout() {
            return poolWaitTimeout;
        }

        int maximumConcurrentRequests() {
            return maximumConcurrentRequests;
        }

        int maximumAttributeValues() {
            return maximumAttributeValues;
        }

        Set<String> requestedAttributes() {
            return requestedAttributes;
        }
    }
}
