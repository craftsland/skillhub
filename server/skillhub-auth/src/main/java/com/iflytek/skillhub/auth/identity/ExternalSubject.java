package com.iflytek.skillhub.auth.identity;

import java.util.Objects;
import java.util.regex.Pattern;

record ExternalSubject(
        String type,
        String value
) {
    private static final Pattern TYPE_PATTERN =
            Pattern.compile("[a-z][a-z0-9_]{0,63}");

    ExternalSubject {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(value, "value");
        if (!TYPE_PATTERN.matcher(type).matches()) {
            throw new IllegalArgumentException("Invalid external subject type");
        }
        if (value.isBlank()
                || value.length()
                > ProviderAssertionLimits.MAX_SUBJECT_VALUE_LENGTH
                || value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("Invalid external subject value");
        }
    }
}
