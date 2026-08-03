package com.iflytek.skillhub.auth.provider;

import com.iflytek.skillhub.auth.identity.EmailAssurance;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Server-owned identity-domain metadata contributed by a trusted adapter.
 *
 * <p>The definition is read during registry reconciliation. It must not be
 * assembled from an authentication response or other caller-controlled data.</p>
 */
public record ProviderInstanceDefinition(
        String providerCode,
        String protocol,
        String canonicalAuthority,
        String displayName,
        String primarySubjectType,
        String legacyPrimarySubjectType,
        Map<String, SubjectNormalization> subjectNormalizations,
        List<String> displayNameAttributes,
        List<String> emailAttributes,
        List<String> avatarAttributes,
        EmailAssurance emailAssuranceLimit,
        boolean authoritativeEmailSource,
        boolean enabled
) {
    private static final Pattern PROVIDER_CODE_PATTERN =
            Pattern.compile("[a-z0-9][a-z0-9._-]{0,63}");
    private static final Pattern PROTOCOL_PATTERN =
            Pattern.compile("[a-z][a-z0-9_-]{0,31}");
    private static final Pattern SUBJECT_TYPE_PATTERN =
            Pattern.compile("[a-z][a-z0-9_]{0,63}");
    private static final Pattern ATTRIBUTE_KEY_PATTERN =
            Pattern.compile("[A-Za-z][A-Za-z0-9_.:-]{0,127}");

    public ProviderInstanceDefinition {
        Objects.requireNonNull(providerCode, "providerCode");
        Objects.requireNonNull(protocol, "protocol");
        Objects.requireNonNull(canonicalAuthority, "canonicalAuthority");
        Objects.requireNonNull(displayName, "displayName");
        Objects.requireNonNull(primarySubjectType, "primarySubjectType");
        Objects.requireNonNull(
                legacyPrimarySubjectType,
                "legacyPrimarySubjectType");
        Objects.requireNonNull(
                subjectNormalizations,
                "subjectNormalizations");
        Objects.requireNonNull(displayNameAttributes, "displayNameAttributes");
        Objects.requireNonNull(emailAttributes, "emailAttributes");
        Objects.requireNonNull(avatarAttributes, "avatarAttributes");
        Objects.requireNonNull(emailAssuranceLimit, "emailAssuranceLimit");
        if (authoritativeEmailSource
                && emailAssuranceLimit != EmailAssurance.AUTHORITATIVE) {
            throw new IllegalArgumentException(
                    "Authoritative email source requires authoritative assurance limit");
        }

        if (!PROVIDER_CODE_PATTERN.matcher(providerCode).matches()) {
            throw new IllegalArgumentException("Invalid provider code");
        }
        if (!PROTOCOL_PATTERN.matcher(protocol).matches()) {
            throw new IllegalArgumentException("Invalid protocol code");
        }
        if (canonicalAuthority.isBlank()
                || canonicalAuthority.length() > 512) {
            throw new IllegalArgumentException("Invalid provider authority");
        }
        if (displayName.isBlank() || displayName.length() > 128) {
            throw new IllegalArgumentException(
                    "Invalid provider display name");
        }
        if (!SUBJECT_TYPE_PATTERN.matcher(primarySubjectType).matches()
                || !SUBJECT_TYPE_PATTERN
                        .matcher(legacyPrimarySubjectType)
                        .matches()) {
            throw new IllegalArgumentException("Invalid subject type");
        }

        subjectNormalizations = Map.copyOf(subjectNormalizations);
        if (!subjectNormalizations.containsKey(primarySubjectType)
                || !subjectNormalizations
                        .containsKey(legacyPrimarySubjectType)) {
            throw new IllegalArgumentException(
                    "Primary subject types must have normalization rules");
        }
        if (subjectNormalizations.entrySet().stream()
                .anyMatch(entry -> entry.getKey() == null
                        || !SUBJECT_TYPE_PATTERN
                                .matcher(entry.getKey())
                                .matches()
                        || entry.getValue() == null)) {
            throw new IllegalArgumentException(
                    "Invalid subject normalization rule");
        }

        displayNameAttributes = copyAttributeKeys(
                displayNameAttributes,
                "displayNameAttributes");
        emailAttributes = copyAttributeKeys(
                emailAttributes,
                "emailAttributes");
        avatarAttributes = copyAttributeKeys(
                avatarAttributes,
                "avatarAttributes");
    }

    public ProviderInstanceDefinition(
            String providerCode,
            String protocol,
            String canonicalAuthority,
            String displayName,
            String primarySubjectType,
            String legacyPrimarySubjectType,
            Map<String, SubjectNormalization> subjectNormalizations,
            List<String> displayNameAttributes,
            List<String> emailAttributes,
            List<String> avatarAttributes,
            EmailAssurance emailAssuranceLimit,
            boolean enabled) {
        this(
                providerCode,
                protocol,
                canonicalAuthority,
                displayName,
                primarySubjectType,
                legacyPrimarySubjectType,
                subjectNormalizations,
                displayNameAttributes,
                emailAttributes,
                avatarAttributes,
                emailAssuranceLimit,
                false,
                enabled);
    }

    public ProviderInstanceDefinition(
            String providerCode,
            String protocol,
            String canonicalAuthority,
            String displayName,
            String primarySubjectType,
            String legacyPrimarySubjectType,
            Map<String, SubjectNormalization> subjectNormalizations,
            List<String> displayNameAttributes,
            List<String> emailAttributes,
            List<String> avatarAttributes,
            EmailAssurance emailAssuranceLimit) {
        this(
                providerCode,
                protocol,
                canonicalAuthority,
                displayName,
                primarySubjectType,
                legacyPrimarySubjectType,
                subjectNormalizations,
                displayNameAttributes,
                emailAttributes,
                avatarAttributes,
                emailAssuranceLimit,
                false,
                true);
    }

    private static List<String> copyAttributeKeys(
            List<String> values,
            String field) {
        List<String> copied = List.copyOf(values);
        if (copied.stream().anyMatch(value -> value == null
                || !ATTRIBUTE_KEY_PATTERN.matcher(value).matches())) {
            throw new IllegalArgumentException(
                    "Invalid provider attribute key in " + field);
        }
        return copied;
    }
}
