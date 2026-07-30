package com.iflytek.skillhub.auth.identity;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

record ProviderDescriptor(
        String providerCode,
        String protocol,
        String canonicalAuthority,
        String displayName,
        String primarySubjectType,
        Set<String> allowedSubjectTypes,
        SubjectCanonicalizer subjectCanonicalizer,
        List<String> displayNameAttributes,
        List<String> emailAttributes,
        List<String> avatarAttributes,
        EmailAssurance emailAssuranceLimit
) {
    private static final Pattern PROVIDER_CODE_PATTERN =
            Pattern.compile("[a-z0-9][a-z0-9._-]{0,63}");
    private static final Pattern PROTOCOL_PATTERN =
            Pattern.compile("[a-z][a-z0-9_-]{0,31}");

    ProviderDescriptor {
        Objects.requireNonNull(providerCode, "providerCode");
        Objects.requireNonNull(protocol, "protocol");
        Objects.requireNonNull(canonicalAuthority, "canonicalAuthority");
        Objects.requireNonNull(displayName, "displayName");
        Objects.requireNonNull(primarySubjectType, "primarySubjectType");
        Objects.requireNonNull(allowedSubjectTypes, "allowedSubjectTypes");
        Objects.requireNonNull(subjectCanonicalizer, "subjectCanonicalizer");
        Objects.requireNonNull(displayNameAttributes, "displayNameAttributes");
        Objects.requireNonNull(emailAttributes, "emailAttributes");
        Objects.requireNonNull(avatarAttributes, "avatarAttributes");
        Objects.requireNonNull(emailAssuranceLimit, "emailAssuranceLimit");

        if (!PROVIDER_CODE_PATTERN.matcher(providerCode).matches()) {
            throw new IllegalArgumentException("Invalid provider code");
        }
        if (!PROTOCOL_PATTERN.matcher(protocol).matches()) {
            throw new IllegalArgumentException("Invalid protocol code");
        }
        if (canonicalAuthority.isBlank() || canonicalAuthority.length() > 512) {
            throw new IllegalArgumentException("Invalid provider authority");
        }
        if (displayName.isBlank() || displayName.length() > 128) {
            throw new IllegalArgumentException("Invalid provider display name");
        }
        allowedSubjectTypes = Set.copyOf(allowedSubjectTypes);
        if (!allowedSubjectTypes.contains(primarySubjectType)) {
            throw new IllegalArgumentException("Primary subject type is not allowed");
        }
        displayNameAttributes = List.copyOf(displayNameAttributes);
        emailAttributes = List.copyOf(emailAttributes);
        avatarAttributes = List.copyOf(avatarAttributes);
    }
}
