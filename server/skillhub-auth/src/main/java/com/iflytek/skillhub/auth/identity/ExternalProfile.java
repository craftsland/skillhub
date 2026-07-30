package com.iflytek.skillhub.auth.identity;

import java.net.URI;
import java.util.Objects;
import java.util.Optional;

record ExternalProfile(
        String displayName,
        Optional<EmailClaim> email,
        Optional<URI> avatarUrl
) {
    ExternalProfile {
        Objects.requireNonNull(displayName, "displayName");
        Objects.requireNonNull(email, "email");
        Objects.requireNonNull(avatarUrl, "avatarUrl");
        if (displayName.isBlank() || displayName.length() > 128) {
            throw new IllegalArgumentException("Invalid external display name");
        }
    }
}
