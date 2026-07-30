package com.iflytek.skillhub.auth.identity;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
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
        if (!result.alternateSubjects().isEmpty()) {
            throw invalidAssertion();
        }

        SubjectCandidate primary = result.primarySubject();
        if (!descriptor.primarySubjectType().equals(primary.type())
                || !descriptor.allowedSubjectTypes().contains(primary.type())) {
            throw invalidAssertion();
        }

        String canonicalValue = descriptor.subjectCanonicalizer()
                .canonicalize(primary.value());
        ExternalSubject primarySubject =
                new ExternalSubject(primary.type(), canonicalValue);
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
                Set.of(),
                profile,
                Map.of(),
                evidence);
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

        Optional<EmailClaim> email = firstValue(
                result.attributes(), descriptor.emailAttributes())
                .filter(value -> !value.value().isBlank())
                .map(value -> new EmailClaim(
                        value.value(),
                        toEmailAssurance(value.trust())
                                .clampTo(descriptor.emailAssuranceLimit())));

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

    private IdentityCoreException invalidAssertion() {
        return new IdentityCoreException(
                IdentityFailureCode.INVALID_IDENTITY_ASSERTION);
    }
}
