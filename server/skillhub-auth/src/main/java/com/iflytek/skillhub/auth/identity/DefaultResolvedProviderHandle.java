package com.iflytek.skillhub.auth.identity;

import java.util.Objects;

record DefaultResolvedProviderHandle(
        String providerCode
) implements ResolvedProviderHandle {

    DefaultResolvedProviderHandle {
        Objects.requireNonNull(providerCode, "providerCode");
        if (providerCode.isBlank()) {
            throw new IllegalArgumentException(
                    "Provider code must not be blank");
        }
    }
}
