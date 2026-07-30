package com.iflytek.skillhub.auth.identity;

/**
 * Test-only factory for the sealed provider handle.
 */
public final class ResolvedProviderHandleTestFixture {

    private ResolvedProviderHandleTestFixture() {
    }

    public static ResolvedProviderHandle handle(
            String providerCode) {
        return new DefaultResolvedProviderHandle(providerCode);
    }
}
