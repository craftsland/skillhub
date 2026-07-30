package com.iflytek.skillhub.auth.identity;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

record IdentityAssertion(
        ProviderReference provider,
        ExternalSubject primarySubject,
        Set<ExternalSubject> alternateSubjects,
        ExternalProfile profile,
        Map<String, List<String>> mappedAttributes,
        AuthenticationEvidence evidence
) {
    IdentityAssertion {
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(primarySubject, "primarySubject");
        Objects.requireNonNull(alternateSubjects, "alternateSubjects");
        Objects.requireNonNull(profile, "profile");
        Objects.requireNonNull(mappedAttributes, "mappedAttributes");
        Objects.requireNonNull(evidence, "evidence");

        if (alternateSubjects.contains(primarySubject)) {
            throw new IllegalArgumentException(
                    "Primary subject must not also be an alias");
        }
        alternateSubjects = Set.copyOf(alternateSubjects);
        LinkedHashMap<String, List<String>> copied = new LinkedHashMap<>();
        mappedAttributes.forEach((key, values) -> copied.put(key, List.copyOf(values)));
        mappedAttributes = Map.copyOf(copied);
    }

    Set<ExternalSubject> allSubjects() {
        LinkedHashSet<ExternalSubject> subjects = new LinkedHashSet<>();
        subjects.add(primarySubject);
        subjects.addAll(alternateSubjects);
        return Set.copyOf(subjects);
    }

    ExternalSubject requireUniqueSubject(String subjectType) {
        ExternalSubject resolved = null;
        for (ExternalSubject subject : allSubjects()) {
            if (!subject.type().equals(subjectType)) {
                continue;
            }
            if (resolved != null) {
                throw new IdentityCoreException(
                        IdentityFailureCode.INVALID_IDENTITY_ASSERTION);
            }
            resolved = subject;
        }
        if (resolved == null) {
            throw new IdentityCoreException(
                    IdentityFailureCode.IDENTITY_SUBJECT_MISSING);
        }
        return resolved;
    }
}
