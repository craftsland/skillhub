package com.iflytek.skillhub.domain.skill.metadata;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Arrays;
import java.util.Optional;

/**
 * Controlled vocabulary for phase-1 compliance mappings.
 */
public enum ComplianceStandard {
    MITRE_ATTACK("mitre_attack"),
    NIST_CSF("nist_csf"),
    GDPR("gdpr"),
    HIPAA("hipaa"),
    SOC2("soc2");

    private final String value;

    ComplianceStandard(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }

    @JsonCreator
    public static ComplianceStandard fromValue(String value) {
        return findByValue(value)
                .orElseThrow(() -> new IllegalArgumentException("Unknown compliance standard: " + value));
    }

    public static Optional<ComplianceStandard> findByValue(String value) {
        if (value == null) {
            return Optional.empty();
        }
        return Arrays.stream(values())
                .filter(candidate -> candidate.value.equals(value.trim().toLowerCase(java.util.Locale.ROOT)))
                .findFirst();
    }
}
