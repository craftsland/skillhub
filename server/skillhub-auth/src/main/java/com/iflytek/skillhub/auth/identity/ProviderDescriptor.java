package com.iflytek.skillhub.auth.identity;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

record ProviderDescriptor(
        String providerCode,
        String protocol,
        String canonicalAuthority,
        String displayName,
        String primarySubjectType,
        String legacyPrimarySubjectType,
        Map<String, SubjectCanonicalizer> subjectCanonicalizers,
        List<String> displayNameAttributes,
        List<String> emailAttributes,
        List<String> avatarAttributes,
        EmailAssurance emailAssuranceLimit,
        boolean authoritativeEmailSource,
        ProvisioningMode provisioningMode,
        ProfileSyncPolicy profileSyncPolicy
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
        Objects.requireNonNull(
                legacyPrimarySubjectType,
                "legacyPrimarySubjectType");
        Objects.requireNonNull(
                subjectCanonicalizers,
                "subjectCanonicalizers");
        Objects.requireNonNull(displayNameAttributes, "displayNameAttributes");
        Objects.requireNonNull(emailAttributes, "emailAttributes");
        Objects.requireNonNull(avatarAttributes, "avatarAttributes");
        Objects.requireNonNull(emailAssuranceLimit, "emailAssuranceLimit");
        Objects.requireNonNull(provisioningMode, "provisioningMode");
        Objects.requireNonNull(profileSyncPolicy, "profileSyncPolicy");

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
        subjectCanonicalizers = Map.copyOf(subjectCanonicalizers);
        if (!subjectCanonicalizers.containsKey(primarySubjectType)) {
            throw new IllegalArgumentException("Primary subject type is not allowed");
        }
        if (!subjectCanonicalizers.containsKey(legacyPrimarySubjectType)) {
            throw new IllegalArgumentException(
                    "Legacy primary subject type is not allowed");
        }
        displayNameAttributes = List.copyOf(displayNameAttributes);
        emailAttributes = List.copyOf(emailAttributes);
        avatarAttributes = List.copyOf(avatarAttributes);
    }

    ProviderDescriptor(
            String providerCode,
            String protocol,
            String canonicalAuthority,
            String displayName,
            String primarySubjectType,
            String legacyPrimarySubjectType,
            Map<String, SubjectCanonicalizer> subjectCanonicalizers,
            List<String> displayNameAttributes,
            List<String> emailAttributes,
            List<String> avatarAttributes,
            EmailAssurance emailAssuranceLimit,
            ProvisioningMode provisioningMode,
            ProfileSyncPolicy profileSyncPolicy) {
        this(
                providerCode,
                protocol,
                canonicalAuthority,
                displayName,
                primarySubjectType,
                legacyPrimarySubjectType,
                subjectCanonicalizers,
                displayNameAttributes,
                emailAttributes,
                avatarAttributes,
                emailAssuranceLimit,
                false,
                provisioningMode,
                profileSyncPolicy);
    }

    ProviderDescriptor(
            String providerCode,
            String protocol,
            String canonicalAuthority,
            String displayName,
            String primarySubjectType,
            String legacyPrimarySubjectType,
            Map<String, SubjectCanonicalizer> subjectCanonicalizers,
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
                subjectCanonicalizers,
                displayNameAttributes,
                emailAttributes,
                avatarAttributes,
                emailAssuranceLimit,
                false,
                ProvisioningMode.AUTO,
                ProfileSyncPolicy.defaults());
    }

    SubjectCanonicalizer canonicalizerFor(String subjectType) {
        SubjectCanonicalizer canonicalizer =
                subjectCanonicalizers.get(subjectType);
        if (canonicalizer == null) {
            throw new IdentityCoreException(
                    IdentityFailureCode.INVALID_IDENTITY_ASSERTION);
        }
        return canonicalizer;
    }
}
