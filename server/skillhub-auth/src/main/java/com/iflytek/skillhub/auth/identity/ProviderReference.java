package com.iflytek.skillhub.auth.identity;

import java.util.Objects;

record ProviderReference(
        String providerCode,
        String protocol,
        String authority
) {
    ProviderReference {
        Objects.requireNonNull(providerCode, "providerCode");
        Objects.requireNonNull(protocol, "protocol");
        Objects.requireNonNull(authority, "authority");
    }
}
