package com.iflytek.skillhub.auth.cas;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;

/**
 * First-party CAS login projection and the exact service value that must be
 * reused for service-ticket validation.
 */
public record CasLoginInitiation(
        URI loginUri,
        String serviceUrl,
        Duration stateTtl
) {
    public CasLoginInitiation {
        Objects.requireNonNull(loginUri, "loginUri");
        Objects.requireNonNull(serviceUrl, "serviceUrl");
        Objects.requireNonNull(stateTtl, "stateTtl");
    }
}
