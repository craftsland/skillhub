package com.iflytek.skillhub.auth.identity;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Candidate stable identifier produced by a protocol adapter before the
 * identity core applies trusted type and canonicalization rules.
 */
public record SubjectCandidate(
        String type,
        String value
) {
    private static final Pattern TYPE_PATTERN =
            Pattern.compile("[a-z][a-z0-9_]{0,63}");
    private static final int ADAPTER_VALUE_LIMIT = 4_096;

    public SubjectCandidate {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(value, "value");
        if (!TYPE_PATTERN.matcher(type).matches()) {
            throw new IllegalArgumentException("Invalid subject candidate type");
        }
        if (value.isBlank()) {
            throw new IllegalArgumentException("Subject candidate value must not be blank");
        }
        if (value.length() > ADAPTER_VALUE_LIMIT) {
            throw new IllegalArgumentException("Subject candidate value is too long");
        }
    }
}
