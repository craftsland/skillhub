package com.iflytek.skillhub.auth.ldap;

import com.iflytek.skillhub.auth.identity.EmailAssurance;
import com.iflytek.skillhub.auth.identity.ProtocolAuthenticationEvidence;
import com.iflytek.skillhub.auth.identity.ProviderAttributeTrust;
import com.iflytek.skillhub.auth.identity.ProviderAttributeValue;
import com.iflytek.skillhub.auth.identity.ProviderAuthenticationResult;
import com.iflytek.skillhub.auth.identity.SubjectCandidate;
import com.iflytek.skillhub.auth.provider.CredentialAuthenticationAdapter;
import com.iflytek.skillhub.auth.provider.CredentialAuthenticationRequest;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationException;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationFailureCode;
import com.iflytek.skillhub.auth.provider.ProviderInstanceDefinition;
import com.iflytek.skillhub.auth.provider.SubjectNormalization;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Maps a verified LDAP bind into provider facts consumed by the unified
 * identity core.
 */
@Component
public final class LdapAuthenticationAdapter
        implements CredentialAuthenticationAdapter {

    static final String USERNAME_ATTRIBUTE = "ldap_username";
    static final String DISPLAY_NAME_ATTRIBUTE = "ldap_display_name";
    static final String EMAIL_ATTRIBUTE = "ldap_email";
    static final String AVATAR_URL_ATTRIBUTE = "ldap_avatar_url";
    private static final int MAX_CREDENTIAL_LENGTH = 4096;
    private static final int MAX_ATTRIBUTE_VALUE_LENGTH = 8192;

    private final LdapProviderConfiguration configuration;
    private final LdapDirectoryClient directoryClient;
    private final LdapAuthenticationMetrics metrics;

    @Autowired
    LdapAuthenticationAdapter(
            LdapProviderConfiguration configuration,
            LdapDirectoryClient directoryClient,
            LdapAuthenticationMetrics metrics) {
        this.configuration = configuration;
        this.directoryClient = directoryClient;
        this.metrics = metrics;
    }

    LdapAuthenticationAdapter(
            LdapProviderConfiguration configuration,
            LdapDirectoryClient directoryClient) {
        this(
                configuration,
                directoryClient,
                LdapAuthenticationMetrics.noop());
    }

    @Override
    public ProviderInstanceDefinition provider() {
        if (!configuration.enabled()) {
            return new ProviderInstanceDefinition(
                    "ldap",
                    "ldap",
                    "disabled",
                    "Corporate Directory",
                    "ldap_entry_uuid",
                    "ldap_entry_uuid",
                    Map.of(
                            "ldap_entry_uuid",
                            SubjectNormalization.EXACT),
                    List.of(
                            DISPLAY_NAME_ATTRIBUTE,
                            USERNAME_ATTRIBUTE),
                    List.of(EMAIL_ATTRIBUTE),
                    List.of(AVATAR_URL_ATTRIBUTE),
                    EmailAssurance.PROVIDER_ASSERTED,
                    false);
        }
        LdapProviderConfiguration.ResolvedLdapProvider resolved =
                configuration.requireResolved();
        return new ProviderInstanceDefinition(
                resolved.providerCode(),
                "ldap",
                resolved.authority(),
                resolved.displayName(),
                resolved.subjectType(),
                resolved.subjectType(),
                Map.of(
                        resolved.subjectType(),
                        SubjectNormalization.EXACT),
                List.of(
                        DISPLAY_NAME_ATTRIBUTE,
                        USERNAME_ATTRIBUTE),
                List.of(EMAIL_ATTRIBUTE),
                List.of(AVATAR_URL_ATTRIBUTE),
                resolved.emailAuthoritative()
                        ? EmailAssurance.AUTHORITATIVE
                        : EmailAssurance.PROVIDER_ASSERTED,
                resolved.emailAuthoritative(),
                true);
    }

    @Override
    public ProviderAuthenticationResult authenticate(
            CredentialAuthenticationRequest request) {
        requireCredential(request == null ? null : request.username());
        requireCredential(request == null ? null : request.password());
        LdapProviderConfiguration.ResolvedLdapProvider resolved;
        try {
            resolved = configuration.requireResolved();
        } catch (RuntimeException exception) {
            throw new ProviderAuthenticationException(
                    ProviderAuthenticationFailureCode
                            .UPSTREAM_MISCONFIGURED);
        }
        LdapAuthenticatedEntry entry;
        try {
            entry = directoryClient.authenticate(resolved, request);
            metrics.recordSuccess(
                    resolved.providerCode(),
                    resolved.transport());
        } catch (ProviderAuthenticationException exception) {
            metrics.recordFailure(
                    resolved.providerCode(),
                    resolved.transport(),
                    exception.getReasonCode());
            throw exception;
        }

        Map<String, List<ProviderAttributeValue>> attributes =
                new LinkedHashMap<>();
        putMapped(
                attributes,
                USERNAME_ATTRIBUTE,
                resolved.usernameAttribute(),
                entry.attributes(),
                ProviderAttributeTrust.ASSERTED);
        putMapped(
                attributes,
                DISPLAY_NAME_ATTRIBUTE,
                resolved.displayNameAttribute(),
                entry.attributes(),
                ProviderAttributeTrust.ASSERTED);
        putMapped(
                attributes,
                EMAIL_ATTRIBUTE,
                resolved.emailAttribute(),
                entry.attributes(),
                ProviderAttributeTrust.ASSERTED);
        putMapped(
                attributes,
                AVATAR_URL_ATTRIBUTE,
                resolved.avatarUrlAttribute(),
                entry.attributes(),
                ProviderAttributeTrust.ASSERTED);

        return new ProviderAuthenticationResult(
                new SubjectCandidate(
                        resolved.subjectType(),
                        entry.subject()),
                List.of(),
                attributes,
                new ProtocolAuthenticationEvidence(
                        "ldap",
                        entry.authenticatedAt(),
                        authenticationMethods(resolved.transport())));
    }

    private Set<String> authenticationMethods(
            LdapTransport transport) {
        return switch (transport) {
            case PLAIN -> Set.of("password", "ldap");
            case STARTTLS -> Set.of("password", "starttls");
            case LDAPS -> Set.of("password", "ldaps");
        };
    }

    private void putMapped(
            Map<String, List<ProviderAttributeValue>> target,
            String targetKey,
            Optional<String> sourceKey,
            Map<String, List<String>> source,
            ProviderAttributeTrust trust) {
        if (sourceKey.isEmpty()) {
            return;
        }
        List<String> values = source.get(sourceKey.orElseThrow());
        if (values == null) {
            return;
        }
        List<ProviderAttributeValue> mapped = new ArrayList<>();
        for (String value : values) {
            if (!value.isBlank()
                    && value.length() <= MAX_ATTRIBUTE_VALUE_LENGTH) {
                mapped.add(new ProviderAttributeValue(value, trust));
            }
        }
        if (!mapped.isEmpty()) {
            target.put(targetKey, List.copyOf(mapped));
        }
    }

    private void requireCredential(String value) {
        if (value == null
                || value.isBlank()
                || value.length() > MAX_CREDENTIAL_LENGTH
                || value.chars().anyMatch(Character::isISOControl)) {
            throw new ProviderAuthenticationException(
                    ProviderAuthenticationFailureCode
                            .UPSTREAM_INVALID_CREDENTIALS);
        }
    }
}
