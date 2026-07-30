package com.iflytek.skillhub.auth.identity;

import java.util.LinkedHashMap;
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

        alternateSubjects = Set.copyOf(alternateSubjects);
        LinkedHashMap<String, List<String>> copied = new LinkedHashMap<>();
        mappedAttributes.forEach((key, values) -> copied.put(key, List.copyOf(values)));
        mappedAttributes = Map.copyOf(copied);
    }
}
