package com.iflytek.skillhub.auth.identity;

import java.util.Objects;

record ExternalSubject(
        String type,
        String value
) {
    ExternalSubject {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(value, "value");
        if (type.isBlank() || type.length() > 64) {
            throw new IllegalArgumentException("Invalid external subject type");
        }
        if (value.isBlank() || value.length() > ProviderAssertionLimits.MAX_SUBJECT_VALUE_LENGTH) {
            throw new IllegalArgumentException("Invalid external subject value");
        }
    }
}
