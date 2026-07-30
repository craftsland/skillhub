package com.iflytek.skillhub.auth.identity;

/**
 * Opaque handle issued only after a server-owned provider route is resolved.
 */
public sealed interface ResolvedProviderHandle
        permits DefaultResolvedProviderHandle {

    String providerCode();
}
