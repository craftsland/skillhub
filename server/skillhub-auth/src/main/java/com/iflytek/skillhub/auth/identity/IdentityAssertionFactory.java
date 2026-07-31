package com.iflytek.skillhub.auth.identity;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Component;

@Component
final class IdentityAssertionFactory {

    IdentityAssertion create(
            ProviderDescriptor descriptor,
            ProviderAuthenticationResult result) {
        if (!descriptor.protocol().equals(result.evidence().protocol())) {
            throw invalidAssertion();
        }
        validatePayload(result);

        SubjectCandidate primary = result.primarySubject();
        if (!descriptor.primarySubjectType().equals(primary.type())
                || !descriptor.subjectCanonicalizers()
                        .containsKey(primary.type())) {
            throw invalidAssertion();
        }

        String canonicalValue = descriptor.canonicalizerFor(primary.type())
                .canonicalize(primary.value());
        ExternalSubject primarySubject =
                new ExternalSubject(primary.type(), canonicalValue);
        Set<ExternalSubject> alternateSubjects =
                canonicalizeAlternates(
                        descriptor,
                        result.alternateSubjects(),
                        primarySubject);
        validateLegacySubject(
                descriptor,
                primarySubject,
                alternateSubjects);
        ExternalProfile profile = createProfile(descriptor, result, primarySubject);
        AuthenticationEvidence evidence = new AuthenticationEvidence(
                descriptor.protocol(),
                result.evidence().authenticatedAt(),
                result.evidence().authenticationMethods());

        return new IdentityAssertion(
                new ProviderReference(
                        descriptor.providerCode(),
                        descriptor.protocol(),
                        descriptor.canonicalAuthority()),
                primarySubject,
                alternateSubjects,
                profile,
                Map.of(),
                evidence);
    }

    private Set<ExternalSubject> canonicalizeAlternates(
            ProviderDescriptor descriptor,
            List<SubjectCandidate> candidates,
            ExternalSubject primarySubject) {
        if (candidates.size()
                > ProviderAssertionLimits.MAX_ALTERNATE_SUBJECT_COUNT) {
            throw invalidAssertion();
        }
        LinkedHashSet<ExternalSubject> canonical = new LinkedHashSet<>();
        for (SubjectCandidate candidate : candidates) {
            ExternalSubject subject = new ExternalSubject(
                    candidate.type(),
                    descriptor.canonicalizerFor(candidate.type())
                            .canonicalize(candidate.value()));
            if (subject.equals(primarySubject) || !canonical.add(subject)) {
                throw invalidAssertion();
            }
        }
        return Set.copyOf(canonical);
    }

    private void validateLegacySubject(
            ProviderDescriptor descriptor,
            ExternalSubject primarySubject,
            Set<ExternalSubject> alternateSubjects) {
        ExternalSubject legacy = null;
        if (primarySubject.type().equals(
                descriptor.legacyPrimarySubjectType())) {
            legacy = primarySubject;
        }
        for (ExternalSubject subject : alternateSubjects) {
            if (!subject.type().equals(
                    descriptor.legacyPrimarySubjectType())) {
                continue;
            }
            if (legacy != null) {
                throw invalidAssertion();
            }
            legacy = subject;
        }
        if (legacy == null
                || legacy.value().length()
                > ProviderAssertionLimits.MAX_LEGACY_SUBJECT_VALUE_LENGTH) {
            throw invalidAssertion();
        }
    }

    private ExternalProfile createProfile(
            ProviderDescriptor descriptor,
            ProviderAuthenticationResult result,
            ExternalSubject primarySubject) {
        String displayName = firstValue(
                result.attributes(), descriptor.displayNameAttributes())
                .map(ProviderAttributeValue::value)
                .filter(value -> !value.isBlank() && value.length() <= 128)
                .orElseGet(() -> {
                    if (primarySubject.value().length() > 128) {
                        throw invalidAssertion();
                    }
                    return primarySubject.value();
                });

        Optional<EmailClaim> email = selectEmail(
                descriptor,
                result.attributes());

        Optional<URI> avatarUrl = firstValue(
                result.attributes(), descriptor.avatarAttributes())
                .filter(value -> !value.value().isBlank())
                .map(ProviderAttributeValue::value)
                .map(this::parseAvatarUri);

        return new ExternalProfile(displayName, email, avatarUrl);
    }

    private Optional<ProviderAttributeValue> firstValue(
            Map<String, List<ProviderAttributeValue>> attributes,
            List<String> trustedAttributeOrder) {
        for (String attribute : trustedAttributeOrder) {
            List<ProviderAttributeValue> values = attributes.get(attribute);
            if (values != null && !values.isEmpty()) {
                return Optional.of(values.getFirst());
            }
        }
        return Optional.empty();
    }

    private Optional<EmailClaim> selectEmail(
            ProviderDescriptor descriptor,
            Map<String, List<ProviderAttributeValue>> attributes) {
        List<EmailCandidate> candidates = new ArrayList<>();
        for (int attributePriority = 0;
                attributePriority < descriptor.emailAttributes().size();
                attributePriority++) {
            String attribute = descriptor.emailAttributes()
                    .get(attributePriority);
            List<ProviderAttributeValue> values = attributes.get(attribute);
            if (values == null) {
                continue;
            }
            for (ProviderAttributeValue value : values) {
                Optional<String> normalized = normalizeEmail(value.value());
                if (normalized.isEmpty()) {
                    continue;
                }
                EmailAssurance assurance = emailAssurance(
                        descriptor,
                        value).clampTo(descriptor.emailAssuranceLimit());
                candidates.add(new EmailCandidate(
                        normalized.orElseThrow(),
                        assurance,
                        attributePriority));
            }
        }
        if (candidates.isEmpty()) {
            return Optional.empty();
        }

        Map<String, EmailCandidate> deduplicated =
                new LinkedHashMap<>();
        for (EmailCandidate candidate : candidates) {
            deduplicated.merge(
                    candidate.value(),
                    candidate,
                    (existing, duplicate) -> existing.assurance().ordinal()
                            >= duplicate.assurance().ordinal()
                            ? existing
                            : duplicate);
        }

        long trustedEmailCount = deduplicated.values().stream()
                .filter(candidate -> candidate.assurance()
                        .isVerifiedOrAuthoritative())
                .map(EmailCandidate::value)
                .distinct()
                .count();
        if (trustedEmailCount > 1) {
            throw invalidAssertion();
        }

        return deduplicated.values().stream()
                .min(Comparator
                        .comparing(
                                EmailCandidate::assurance,
                                Comparator.reverseOrder())
                        .thenComparingInt(EmailCandidate::attributePriority)
                        .thenComparing(EmailCandidate::value))
                .map(candidate -> new EmailClaim(
                        candidate.value(),
                        candidate.assurance()));
    }

    private Optional<String> normalizeEmail(String value) {
        if (value == null) {
            return Optional.empty();
        }
        String normalized = value.strip().toLowerCase(Locale.ROOT);
        int at = normalized.indexOf('@');
        if (normalized.length() > 256
                || at <= 0
                || at != normalized.lastIndexOf('@')
                || at == normalized.length() - 1
                || normalized.chars().anyMatch(
                        character -> Character.isISOControl(character)
                                || Character.isWhitespace(character))) {
            return Optional.empty();
        }
        return Optional.of(normalized);
    }

    private record EmailCandidate(
            String value,
            EmailAssurance assurance,
            int attributePriority) {
    }

    private URI parseAvatarUri(String value) {
        try {
            URI uri = new URI(value);
            if (!uri.isAbsolute()
                    || (!"https".equalsIgnoreCase(uri.getScheme())
                    && !"http".equalsIgnoreCase(uri.getScheme()))) {
                throw invalidAssertion();
            }
            return uri;
        } catch (URISyntaxException exception) {
            throw new IdentityCoreException(
                    IdentityFailureCode.INVALID_IDENTITY_ASSERTION,
                    exception);
        }
    }

    private void validatePayload(ProviderAuthenticationResult result) {
        if (result.attributes().size() > ProviderAssertionLimits.MAX_ATTRIBUTE_COUNT) {
            throw invalidAssertion();
        }
        int totalLength = result.primarySubject().type().length()
                + result.primarySubject().value().length();
        for (SubjectCandidate alternate : result.alternateSubjects()) {
            totalLength += alternate.type().length() + alternate.value().length();
        }
        for (Map.Entry<String, List<ProviderAttributeValue>> entry
                : result.attributes().entrySet()) {
            if (entry.getValue().size()
                    > ProviderAssertionLimits.MAX_VALUES_PER_ATTRIBUTE) {
                throw invalidAssertion();
            }
            totalLength += entry.getKey().length();
            for (ProviderAttributeValue value : entry.getValue()) {
                if (value.value().length()
                        > ProviderAssertionLimits.MAX_ATTRIBUTE_VALUE_LENGTH) {
                    throw invalidAssertion();
                }
                totalLength += value.value().length();
            }
        }
        if (totalLength > ProviderAssertionLimits.MAX_TOTAL_PAYLOAD_LENGTH) {
            throw invalidAssertion();
        }
    }

    private EmailAssurance toEmailAssurance(ProviderAttributeTrust trust) {
        return switch (trust) {
            case UNVERIFIED -> EmailAssurance.UNVERIFIED;
            case ASSERTED -> EmailAssurance.PROVIDER_ASSERTED;
            case VERIFIED -> EmailAssurance.VERIFIED;
        };
    }

    private EmailAssurance emailAssurance(
            ProviderDescriptor descriptor,
            ProviderAttributeValue value) {
        if (descriptor.authoritativeEmailSource()
                && value.trust() == ProviderAttributeTrust.ASSERTED) {
            return EmailAssurance.AUTHORITATIVE;
        }
        return toEmailAssurance(value.trust());
    }

    private IdentityCoreException invalidAssertion() {
        return new IdentityCoreException(
                IdentityFailureCode.INVALID_IDENTITY_ASSERTION);
    }
}
