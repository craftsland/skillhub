package com.iflytek.skillhub.auth.identity;

import java.util.Objects;

record EmailClaim(
        String value,
        EmailAssurance assurance
) {
    EmailClaim {
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(assurance, "assurance");
        if (value.isBlank() || value.length() > 256 || !value.contains("@")) {
            throw new IllegalArgumentException("Invalid email claim");
        }
    }
}
